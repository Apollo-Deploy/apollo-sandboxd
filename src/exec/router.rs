//! Bounded routing of unsolicited guest events into per-exec durable journals.
//!
//! The router deliberately has no guest or API ownership. RuntimeService owns
//! one router per live VM and feeds it from `GuestConnection::subscribe_events`.
use super::{ExecOutputBridge, JournalPage, OutputJournal, OutputSink};
use crate::error::Result;
use crate::guest::GuestPeer;
use crate::security::path::SecureDir;
use guest_protocol::OutputPolicy;
use sandboxd_protocol::exec::ExecSummary;
use sandboxd_protocol::{ExecId, codec};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const MANIFEST: &str = "exec.manifest";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecManifest {
    pub(crate) exec: ExecId,
    pub(crate) request_digest: [u8; 32],
    pub(crate) output_policy: OutputPolicy,
    pub(crate) output_bytes: u64,
}

pub struct ExecEventRouter {
    pub(super) bridge: Mutex<ExecOutputBridge>,
}

impl ExecEventRouter {
    pub fn new(root: &Path) -> Result<Self> {
        std::fs::create_dir_all(root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            bridge: Mutex::new(ExecOutputBridge::new(root)?),
        })
    }

    /// Admission must complete before the caller sends `ExecStart`.
    pub fn register(
        &self,
        exec: ExecId,
        journal: OutputJournal,
        stdout: Option<OutputSink>,
        stderr: Option<OutputSink>,
        policy: OutputPolicy,
        output_limit: u64,
    ) -> Result<()> {
        self.bridge
            .lock()
            .map_err(|_| crate::error::Error::State)?
            .register(exec, journal, stdout, stderr, policy, output_limit)
    }

    pub fn contains(&self, exec: &ExecId) -> Result<bool> {
        Ok(self
            .bridge
            .lock()
            .map_err(|_| crate::error::Error::State)?
            .contains(exec))
    }

    /// Publishes non-secret execution identity before `ExecStart` is sent.
    pub fn prepare_manifest(
        root: &Path,
        exec: &ExecId,
        request_digest: [u8; 32],
        output_policy: OutputPolicy,
        output_bytes: u64,
    ) -> Result<PathBuf> {
        fs::create_dir_all(root)?;
        #[cfg(unix)]
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        let path = root.join(MANIFEST);
        let bytes = codec::encode_body(&ExecManifest {
            exec: exec.clone(),
            request_digest,
            output_policy,
            output_bytes,
        })?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        use std::io::Write;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::File::open(root)?.sync_all()?;
        Ok(path)
    }

    pub fn manifest_matches(
        root: &Path,
        exec: &ExecId,
        request_digest: [u8; 32],
        output_bytes: u64,
    ) -> Result<bool> {
        let bytes = fs::read(root.join(exec.as_str()).join(MANIFEST))?;
        let manifest: ExecManifest = codec::decode_body(&bytes)?;
        Ok(manifest.exec == *exec
            && manifest.request_digest == request_digest
            && manifest.output_bytes == output_bytes)
    }

    /// Handles one unsolicited event. Output is journaled before sink write;
    /// a required sink error is returned so the owner can cancel the exec.
    pub fn handle(&self, peer: GuestPeer) -> Result<()> {
        self.bridge
            .lock()
            .map_err(|_| crate::error::Error::State)?
            .handle(peer.message)
    }

    pub fn replay(&self, exec: &ExecId, from: u64, limit: u16) -> Result<JournalPage> {
        self.bridge
            .lock()
            .map_err(|_| crate::error::Error::State)?
            .replay(exec, from, limit)
    }

    pub fn exit(&self, exec: &ExecId) -> Result<Option<(Option<i32>, Option<u8>, bool)>> {
        Ok(self
            .bridge
            .lock()
            .map_err(|_| crate::error::Error::State)?
            .exit(exec))
    }

    pub fn list(&self, after: Option<&ExecId>, limit: u16) -> Result<Vec<ExecSummary>> {
        self.bridge
            .lock()
            .map_err(|_| crate::error::Error::State)?
            .list(after, limit)
    }

    pub fn take_output_loss(&self, exec: &ExecId) -> Result<u64> {
        Ok(self
            .bridge
            .lock()
            .map_err(|_| crate::error::Error::State)?
            .take_output_loss(exec))
    }

    pub fn take_output_gaps(&self, exec: &ExecId) -> Result<Vec<u64>> {
        Ok(self
            .bridge
            .lock()
            .map_err(|_| crate::error::Error::State)?
            .take_output_gaps(exec))
    }

    pub fn take_sink_failures(&self) -> Result<Vec<ExecId>> {
        Ok(self
            .bridge
            .lock()
            .map_err(|_| crate::error::Error::State)?
            .take_sink_failures())
    }

    pub fn record_transport_reset(&self) -> Result<()> {
        self.bridge
            .lock()
            .map_err(|_| crate::error::Error::State)?
            .record_transport_reset()
    }

    pub fn snapshot_capture(
        &self,
        root: &Path,
        id: &sandboxd_protocol::SnapshotId,
        max_bytes: u64,
        persist: &mut dyn FnMut(&super::OutputSnapshotRecord) -> Result<()>,
    ) -> Result<super::OutputSnapshotRecord> {
        self.validate_snapshot_capture()?;
        let bridge = self.bridge.lock().map_err(|_| crate::error::Error::State)?;
        let inventory = bridge.snapshot_inventory()?;
        super::snapshot::capture(root, id.as_str(), max_bytes, persist, &inventory)
    }

    /// Required output sinks cannot be recreated during restore without new
    /// descriptors. Refuse a snapshot of a still-running Required execution
    /// rather than silently downgrading its delivery guarantee.
    pub fn validate_snapshot_capture(&self) -> Result<()> {
        let bridge = self.bridge.lock().map_err(|_| crate::error::Error::State)?;
        for item in bridge.snapshot_inventory()? {
            if item.exit.is_some() {
                continue;
            }
            let dir = SecureDir::open(&item.source)?;
            let mut manifest = dir.open_file(MANIFEST, false)?;
            if manifest.metadata()?.len() > 1 << 20 {
                return Err(crate::error::Error::State);
            }
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(
                &mut std::io::Read::take(&mut manifest, (1 << 20) + 1),
                &mut bytes,
            )?;
            if bytes.len() > 1 << 20 {
                return Err(crate::error::Error::State);
            }
            let policy: ExecManifest = codec::decode_body(&bytes)?;
            if matches!(policy.output_policy, OutputPolicy::Required) {
                return Err(crate::error::Error::Api(sandboxd_protocol::ApiError::new(
                    sandboxd_protocol::ErrorCode::UnsupportedCapability,
                    "snapshot restore requires replacement descriptors for active required output",
                )));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn snapshot_restore(
        record: &super::OutputSnapshotRecord,
        new_output_root: &Path,
    ) -> Result<()> {
        super::snapshot::restore(record, new_output_root)
    }

    pub fn snapshot_restore_journaled(
        record: &super::OutputSnapshotRecord,
        root: &Path,
        persist: &mut dyn FnMut(&super::OutputSnapshotRecord) -> Result<()>,
    ) -> Result<()> {
        super::snapshot::restore_journaled(record, root, persist)
    }

    pub fn snapshot_delete(record: &super::OutputSnapshotRecord) -> Result<()> {
        super::snapshot::delete(record)
    }

    pub fn snapshot_verify(record: &super::OutputSnapshotRecord) -> Result<()> {
        super::snapshot::verify(record)
    }

    /// Runs until the guest transport closes or the bounded event stream
    /// reports lag. A lagged subscriber is a hard output-integrity failure;
    /// callers must mark the session degraded rather than silently continue.
    pub async fn run(
        self: Arc<Self>,
        mut events: tokio::sync::broadcast::Receiver<GuestPeer>,
    ) -> Result<()> {
        let (tx, rx) = std::sync::mpsc::sync_channel::<GuestPeer>(128);
        let router = Arc::clone(&self);
        let worker = tokio::task::spawn_blocking(move || -> Result<()> {
            while let Ok(peer) = rx.recv() {
                router.handle(peer)?;
            }
            Ok(())
        });
        loop {
            match events.recv().await {
                Ok(peer) => tx
                    .try_send(peer)
                    .map_err(|_| crate::error::Error::Config("guest event backlog exhausted"))?,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    drop(tx);
                    worker.await.map_err(|_| crate::error::Error::State)??;
                    return Err(crate::error::Error::Config("guest event stream closed"));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    drop(tx);
                    let _ = worker.await;
                    return Err(crate::error::Error::Config("guest event stream lagged"));
                }
            }
        }
    }
}
