use super::{JournalPage, OutputJournal, OutputSink};
use crate::error::{Error, Result};
use guest_protocol::{GuestMessage, OutputPolicy, OutputRecord, Stream};
use sandboxd_protocol::ExecId;
use sandboxd_protocol::codec;
use sandboxd_protocol::exec::ExecSummary;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

pub struct ExecOutputBridge {
    journals: HashMap<ExecId, OutputJournal>,
    sinks: HashMap<ExecId, (Option<OutputSink>, Option<OutputSink>)>,
    output_limits: HashMap<ExecId, u64>,
    output_bytes: HashMap<ExecId, u64>,
    root: PathBuf,
    losses: HashMap<ExecId, u64>,
    gaps: HashMap<ExecId, Vec<u64>>,
    exits: HashMap<ExecId, (Option<i32>, Option<u8>, bool)>,
    sink_failures: Vec<ExecId>,
}

pub(crate) struct SnapshotExec {
    pub exec: ExecId,
    pub source: PathBuf,
    pub high_watermark: u64,
    pub exit: Option<(Option<i32>, Option<u8>, bool)>,
    pub max_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn journal_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private root");
        root
    }

    #[test]
    fn required_policy_admits_only_complete_sink_pair() {
        let root = journal_root();
        let exec = ExecId::new("exec").expect("exec");
        let path = root
            .path()
            .canonicalize()
            .expect("canonical root")
            .join(exec.as_str());
        std::fs::create_dir(&path).expect("journal directory");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("private journal directory");
        let journal = OutputJournal::open(&path, exec.clone(), 1 << 20).expect("journal");
        let mut bridge = ExecOutputBridge::new(root.path()).expect("bridge");
        assert!(
            bridge
                .register(exec, journal, None, None, OutputPolicy::Required, 1 << 20)
                .is_err()
        );
    }

    #[test]
    fn best_effort_sink_loss_is_explicit_and_journaled() {
        let root = journal_root();
        let exec = ExecId::new("exec").expect("exec");
        let path = root
            .path()
            .canonicalize()
            .expect("canonical root")
            .join(exec.as_str());
        std::fs::create_dir(&path).expect("journal directory");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("private journal directory");
        let journal = OutputJournal::open(&path, exec.clone(), 1 << 20).expect("journal");
        let mut bridge = ExecOutputBridge::new(root.path()).expect("bridge");
        let (reader, writer) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        let sink_fd = rustix::io::dup(&writer).expect("dup sink");
        drop(reader);
        let sink = OutputSink::new(sink_fd, OutputPolicy::BestEffort).expect("sink");
        bridge
            .register(
                exec.clone(),
                journal,
                Some(sink),
                None,
                OutputPolicy::BestEffort,
                1 << 20,
            )
            .expect("best effort admission");
        bridge
            .handle(GuestMessage::Output {
                record: OutputRecord {
                    exec: exec.clone(),
                    stream: Stream::Stdout,
                    sequence: 1,
                    timestamp_unix_ms: 1,
                    flags: 0,
                    payload: b"raw\0bytes".to_vec(),
                },
            })
            .expect("journal output");
        assert_eq!(bridge.take_output_loss(&exec), b"raw\0bytes".len() as u64);
        assert_eq!(bridge.take_output_gaps(&exec), vec![1]);
        assert!(bridge.contains(&exec));
    }
}
const MAX_REGISTERED_EXECS: usize = 1024;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct ExitRecord {
    exit_code: Option<i32>,
    signal: Option<u8>,
    timed_out: bool,
}
impl ExecOutputBridge {
    pub fn new(root: &Path) -> Result<Self> {
        if !root.is_absolute() {
            return Err(Error::Path);
        }
        Ok(Self {
            journals: HashMap::new(),
            sinks: HashMap::new(),
            output_limits: HashMap::new(),
            output_bytes: HashMap::new(),
            root: root.to_owned(),
            losses: HashMap::new(),
            gaps: HashMap::new(),
            exits: HashMap::new(),
            sink_failures: Vec::new(),
        })
    }

    pub(crate) fn snapshot_inventory(&self) -> Result<Vec<SnapshotExec>> {
        let mut entries = Vec::with_capacity(self.journals.len());
        for (exec, journal) in &self.journals {
            journal.snapshot_checkpoint()?;
            entries.push(SnapshotExec {
                exec: exec.clone(),
                source: journal.directory().to_owned(),
                high_watermark: journal.high_watermark()?,
                exit: self.exits.get(exec).copied(),
                max_bytes: journal.max_bytes(),
            });
        }
        entries.sort_by(|a, b| a.exec.as_str().cmp(b.exec.as_str()));
        Ok(entries)
    }
    pub fn register(
        &mut self,
        exec: ExecId,
        journal: OutputJournal,
        stdout: Option<OutputSink>,
        stderr: Option<OutputSink>,
        policy: OutputPolicy,
        output_limit: u64,
    ) -> Result<()> {
        if matches!(policy, OutputPolicy::Required) && (stdout.is_none() || stderr.is_none()) {
            return Err(Error::Config("required output sink is missing"));
        }
        if self.journals.contains_key(&exec) {
            return Err(Error::State);
        }
        if self.journals.len() >= MAX_REGISTERED_EXECS {
            return Err(Error::Config("execution journal quota exhausted"));
        }
        if output_limit > 1 << 30 || (matches!(policy, OutputPolicy::Required) && output_limit == 0)
        {
            return Err(Error::Config("invalid required output byte limit"));
        }
        self.journals.insert(exec.clone(), journal);
        self.sinks.insert(exec.clone(), (stdout, stderr));
        self.output_limits.insert(exec.clone(), output_limit);
        self.output_bytes.insert(exec, 0);
        Ok(())
    }
    pub(crate) fn register_completed(
        &mut self,
        exec: ExecId,
        journal: OutputJournal,
        exit_code: Option<i32>,
        signal: Option<u8>,
        timed_out: bool,
    ) -> Result<()> {
        // A terminal journal has no future delivery obligation or live sinks.
        self.register(
            exec.clone(),
            journal,
            None,
            None,
            OutputPolicy::Disabled,
            256 << 20,
        )?;
        self.restore_exit(&exec, exit_code, signal, timed_out)
    }
    pub fn handle(&mut self, message: GuestMessage) -> Result<()> {
        match message {
            GuestMessage::Output { record } => self.record(record)?,
            GuestMessage::OutputGap {
                exec,
                from_sequence,
            } => {
                if !self.journals.contains_key(&exec) {
                    return Err(Error::State);
                }
                self.journals
                    .get_mut(&exec)
                    .ok_or(Error::State)?
                    .mark_transport_gap()?;
                let gaps = self.gaps.entry(exec).or_default();
                if gaps.len() >= 64 {
                    return Err(Error::Config("output gap retention exhausted"));
                }
                gaps.push(from_sequence);
            }
            GuestMessage::ExecExit {
                exec,
                exit_code,
                signal,
                timed_out,
            } => {
                if !self.journals.contains_key(&exec) {
                    return Err(Error::State);
                }
                let record = ExitRecord {
                    exit_code,
                    signal,
                    timed_out,
                };
                persist_exit(&self.root, &exec, record)?;
                self.exits.insert(exec, (exit_code, signal, timed_out));
            }
            _ => {}
        }
        Ok(())
    }
    fn record(&mut self, record: OutputRecord) -> Result<()> {
        if record.payload.len() > super::journal::MAX_PAYLOAD_BYTES as usize {
            return Err(Error::Config("guest output chunk exceeds bound"));
        }
        let total = *self.output_bytes.get(&record.exec).ok_or(Error::State)?;
        let limit = *self.output_limits.get(&record.exec).ok_or(Error::State)?;
        let next = total
            .checked_add(record.payload.len() as u64)
            .ok_or(Error::State)?;
        if next > limit {
            self.sink_failures.push(record.exec.clone());
            return Err(crate::error::Error::Api(sandboxd_protocol::ApiError::new(
                sandboxd_protocol::ErrorCode::OutputSinkFailed,
                "execution output byte limit exceeded",
            )));
        }
        self.output_bytes.insert(record.exec.clone(), next);
        let journal = self.journals.get_mut(&record.exec).ok_or(Error::State)?;
        let expected = journal
            .high_watermark()?
            .checked_add(1)
            .ok_or(Error::State)?;
        if record.sequence < expected {
            return Err(Error::State);
        }
        if record.sequence > expected {
            let gaps = self.gaps.entry(record.exec.clone()).or_default();
            if gaps.len() >= 64 {
                return Err(Error::Config("output gap retention exhausted"));
            }
            gaps.push(expected);
        }
        let stored = journal.append_at(
            record.sequence,
            record.stream,
            record.timestamp_unix_ms,
            record.flags,
            &record.payload,
        )?;
        let sinks = self.sinks.get(&record.exec).ok_or(Error::State)?;
        let sink = match stored.stream {
            Stream::Stdout | Stream::Terminal => &sinks.0,
            Stream::Stderr => &sinks.1,
        };
        if let Some(sink) = sink {
            if let Err(_error) = sink.write(&stored.payload) {
                if matches!(sink.policy(), OutputPolicy::Required) {
                    self.sink_failures.push(record.exec.clone());
                    return Err(crate::error::Error::Api(sandboxd_protocol::ApiError::new(
                        sandboxd_protocol::ErrorCode::OutputSinkFailed,
                        "required output sink failed",
                    )));
                }
                *self.losses.entry(record.exec.clone()).or_default() += stored.payload.len() as u64;
                self.gaps
                    .entry(record.exec.clone())
                    .or_default()
                    .push(record.sequence);
            }
        }
        Ok(())
    }
    pub fn take_output_loss(&mut self, exec: &ExecId) -> u64 {
        self.losses.remove(exec).unwrap_or(0)
    }
    pub fn take_sink_failures(&mut self) -> Vec<ExecId> {
        std::mem::take(&mut self.sink_failures)
    }
    /// Returns and clears sequence numbers for which a best-effort sink could
    /// not accept bytes. The journal still contains the bytes, but callers
    /// must surface these sequences as output loss to reattaching clients.
    pub fn take_output_gaps(&mut self, exec: &ExecId) -> Vec<u64> {
        self.gaps.remove(exec).unwrap_or_default()
    }
    pub fn contains(&self, exec: &ExecId) -> bool {
        self.journals.contains_key(exec)
    }
    pub fn exit(&self, exec: &ExecId) -> Option<(Option<i32>, Option<u8>, bool)> {
        self.exits.get(exec).copied()
    }

    pub(crate) fn record_transport_reset(&mut self) -> Result<()> {
        for (exec, journal) in &mut self.journals {
            if !self.exits.contains_key(exec) {
                journal.mark_transport_gap()?;
            }
        }
        Ok(())
    }
    pub(crate) fn restore_transport_gap(&mut self, exec: &ExecId) -> Result<()> {
        self.journals
            .get_mut(exec)
            .ok_or(Error::State)?
            .mark_transport_gap()
    }

    pub fn list(&self, after: Option<&ExecId>, limit: u16) -> Result<Vec<ExecSummary>> {
        if limit == 0 || limit > 256 {
            return Err(Error::Config("execution list bounds"));
        }
        let mut ids: Vec<_> = self.journals.keys().cloned().collect();
        ids.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        let mut result = Vec::new();
        for exec in ids {
            if after.is_some_and(|cursor| exec.as_str() <= cursor.as_str()) {
                continue;
            }
            let journal = self.journals.get(&exec).ok_or(Error::State)?;
            let (exit_code, signal, timed_out) = self
                .exits
                .get(&exec)
                .copied()
                .unwrap_or((None, None, false));
            let running = !self.exits.contains_key(&exec);
            result.push(ExecSummary {
                exec,
                running,
                exit_code,
                signal,
                timed_out,
                output_high_watermark: journal.high_watermark()?,
            });
            if result.len() >= limit as usize {
                break;
            }
        }
        Ok(result)
    }
    pub fn restore_exit(
        &mut self,
        exec: &ExecId,
        exit_code: Option<i32>,
        signal: Option<u8>,
        timed_out: bool,
    ) -> Result<()> {
        if !self.journals.contains_key(exec) {
            return Err(Error::State);
        }
        self.exits
            .insert(exec.clone(), (exit_code, signal, timed_out));
        Ok(())
    }
    pub fn journal_path(&self, exec: &ExecId) -> PathBuf {
        self.root.join(exec.as_str())
    }
    pub fn replay(&self, exec: &ExecId, from: u64, limit: u16) -> Result<JournalPage> {
        self.journals
            .get(exec)
            .ok_or(Error::State)?
            .replay(from, limit)
    }
}

fn persist_exit(root: &Path, exec: &ExecId, record: ExitRecord) -> Result<()> {
    let directory = root.join(exec.as_str());
    let temp = directory.join("exit.cbor.tmp");
    let final_path = directory.join("exit.cbor");
    let bytes = codec::encode_body(&record)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temp)?;
    use std::io::Write;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&temp, &final_path)?;
    fs::File::open(root)?.sync_all()?;
    Ok(())
}
