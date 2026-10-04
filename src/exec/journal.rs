//! Bounded, crash-recoverable raw output journal for one execution.
use crate::{
    error::{Error, Result},
    security::path::SecureDir,
};
use guest_protocol::{OutputRecord, Stream};
use rusqlite::{Connection, TransactionBehavior, params};
use sandboxd_protocol::ExecId;
use sha2::{Digest, Sha256};
use std::{fs::File, path::Path, time::Duration};

const FILE_NAME: &str = "journal.sqlite3";
const PAGE_SIZE: u64 = 4096;
const MAX_JOURNAL_BYTES: u64 = 256 << 20;
pub(crate) const MAX_PAYLOAD_BYTES: u64 = 64 << 10;
// Leave framing/CBOR headroom so an attach response always fits the bounded
// 1 MiB host frame after exec and sequence metadata are encoded.
pub(super) const MAX_REPLAY_BYTES: usize = 768 << 10;
const SCHEMA_VERSION: i64 = 1;

#[derive(Debug)]
pub enum JournalItem {
    Record(OutputRecord),
    Gap {
        from_sequence: u64,
        to_sequence: u64,
    },
}

#[derive(Debug)]
pub struct JournalPage {
    pub items: Vec<JournalItem>,
    pub high_watermark: u64,
    pub transport_gaps: Vec<u64>,
}

pub struct OutputJournal {
    pub(super) connection: Connection,
    pub(super) exec: ExecId,
    max_bytes: u64,
    directory: std::path::PathBuf,
    _lock: File,
}

impl OutputJournal {
    pub fn open(directory_path: &Path, exec: ExecId, max_bytes: u64) -> Result<Self> {
        if !(PAGE_SIZE..=MAX_JOURNAL_BYTES).contains(&max_bytes) {
            return Err(Error::Config("output journal quota is outside bounds"));
        }
        let directory = SecureDir::open(directory_path)?;
        let directory_stat = rustix::fs::fstat(directory.as_fd())?;
        if directory_stat.st_mode & 0o777 != 0o700 {
            return Err(Error::Path);
        }
        let lock = directory.lock("journal.lock")?;
        validate_sidecars(&directory)?;
        let database = directory.open_or_create_private(FILE_NAME)?;
        let before = rustix::fs::fstat(&database)?;
        let path = directory_path.join(FILE_NAME);
        let connection = Connection::open(&path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        let after = directory.stat(FILE_NAME)?;
        if before.st_dev != after.st_dev || before.st_ino != after.st_ino {
            return Err(Error::Path);
        }
        configure(&connection, max_bytes, &exec)?;
        Ok(Self {
            connection,
            exec,
            max_bytes,
            directory: directory_path.to_owned(),
            _lock: lock,
        })
    }

    pub(crate) fn snapshot_checkpoint(&self) -> Result<()> {
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        self.connection.execute_batch("PRAGMA synchronous=FULL;")?;
        let file = File::open(&self.directory)?;
        file.sync_all()?;
        Ok(())
    }

    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }

    pub(crate) fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    pub fn append(
        &mut self,
        stream: Stream,
        timestamp_unix_ms: u64,
        flags: u16,
        payload: &[u8],
    ) -> Result<OutputRecord> {
        let sequence = self.high_watermark()?.checked_add(1).ok_or(Error::State)?;
        self.append_at(sequence, stream, timestamp_unix_ms, flags, payload)
    }

    pub(crate) fn append_at(
        &mut self,
        sequence: u64,
        stream: Stream,
        timestamp_unix_ms: u64,
        flags: u16,
        payload: &[u8],
    ) -> Result<OutputRecord> {
        if payload.is_empty()
            || payload.len() as u64 > MAX_PAYLOAD_BYTES
            || payload.len() as u64 > self.max_bytes
        {
            return Err(Error::Config("output payload is outside bounds"));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        trim_for_incoming(&tx, self.max_bytes, payload.len() as u64)?;
        let high: u64 = tx.query_row("SELECT high_watermark FROM journal_meta", [], |row| {
            row.get(0)
        })?;
        if sequence <= high {
            return Err(Error::State);
        }
        let record = OutputRecord {
            exec: self.exec.clone(),
            stream,
            sequence,
            timestamp_unix_ms,
            flags,
            payload: payload.to_vec(),
        };
        let digest = record_digest(&record);
        tx.execute(
            "INSERT INTO output_records(sequence,timestamp,stream,flags,payload,digest) VALUES (?1,?2,?3,?4,?5,?6)",
            params![sequence, timestamp_unix_ms, stream_code(stream), flags, payload, digest.as_slice()],
        )?;
        tx.execute("UPDATE journal_meta SET high_watermark=?1", [sequence])?;
        tx.commit()?;
        Ok(record)
    }

    pub fn high_watermark(&self) -> Result<u64> {
        Ok(self
            .connection
            .query_row("SELECT high_watermark FROM journal_meta", [], |row| {
                row.get(0)
            })?)
    }
}

fn validate_sidecars(directory: &SecureDir) -> Result<()> {
    for name in ["journal.sqlite3-wal", "journal.sqlite3-shm"] {
        match directory.stat(name) {
            Ok(stat)
                if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                    == rustix::fs::FileType::RegularFile
                    && stat.st_nlink == 1
                    && stat.st_uid == rustix::process::geteuid().as_raw()
                    && stat.st_mode & 0o077 == 0 =>
            {
                continue;
            }
            Ok(_) => return Err(Error::Path),
            Err(Error::Kernel(rustix::io::Errno::NOENT)) => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn configure(connection: &Connection, max_bytes: u64, exec: &ExecId) -> Result<()> {
    let pages = max_bytes
        .checked_add(1 << 20)
        .and_then(|bytes| bytes.checked_add(PAGE_SIZE - 1))
        .ok_or(Error::Config("output journal quota overflow"))?
        / PAGE_SIZE;
    connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF; PRAGMA page_size=4096;")?;
    connection.pragma_update(None, "journal_size_limit", max_bytes as i64)?;
    connection.pragma_update(None, "max_page_count", pages as i64)?;
    connection.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS journal_meta(
           schema_version INTEGER NOT NULL,
           exec_id TEXT NOT NULL,
           max_bytes INTEGER NOT NULL,
           high_watermark INTEGER NOT NULL CHECK(high_watermark >= 0)
         );
         CREATE TABLE IF NOT EXISTS transport_gaps(after_sequence INTEGER PRIMARY KEY CHECK(after_sequence>=0)) STRICT;
         CREATE TABLE IF NOT EXISTS output_records(
           sequence INTEGER PRIMARY KEY,
           timestamp INTEGER NOT NULL,
           stream INTEGER NOT NULL,
           flags INTEGER NOT NULL,
           payload BLOB NOT NULL,
           digest BLOB NOT NULL CHECK(length(digest)=32)
         ) STRICT;
         INSERT INTO journal_meta(schema_version,exec_id,max_bytes,high_watermark)
           SELECT 1, '', 0, 0 WHERE NOT EXISTS (SELECT 1 FROM journal_meta);",
    )?;
    let meta: (i64, String, u64) = connection.query_row(
        "SELECT schema_version,exec_id,max_bytes FROM journal_meta",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if meta.0 != SCHEMA_VERSION {
        return Err(Error::State);
    }
    if meta.1.is_empty() && meta.2 == 0 {
        connection.execute(
            "UPDATE journal_meta SET exec_id=?1,max_bytes=?2 WHERE exec_id='' AND max_bytes=0",
            params![exec.as_str(), max_bytes],
        )?;
    } else if meta.1 != exec.as_str() || meta.2 != max_bytes {
        return Err(Error::State);
    }
    Ok(())
}

fn trim_for_incoming(tx: &rusqlite::Transaction<'_>, max_bytes: u64, incoming: u64) -> Result<()> {
    loop {
        let used: u64 = tx.query_row(
            "SELECT COALESCE(SUM(length(payload)),0) FROM output_records",
            [],
            |row| row.get(0),
        )?;
        if used.saturating_add(incoming) <= max_bytes {
            return Ok(());
        }
        tx.execute(
            "DELETE FROM output_records WHERE sequence=(SELECT sequence FROM output_records ORDER BY sequence LIMIT 1)",
            [],
        )?;
    }
}

fn stream_code(stream: Stream) -> u8 {
    match stream {
        Stream::Stdout => 0,
        Stream::Stderr => 1,
        Stream::Terminal => 2,
    }
}

fn stream_from_code(code: u8) -> Result<Stream> {
    match code {
        0 => Ok(Stream::Stdout),
        1 => Ok(Stream::Stderr),
        2 => Ok(Stream::Terminal),
        _ => Err(Error::State),
    }
}

fn record_digest(record: &OutputRecord) -> Sha256Digest {
    let mut hash = Sha256::new();
    hash.update(b"apollo-sandboxd-output-journal-v1");
    hash.update((record.exec.as_str().len() as u64).to_le_bytes());
    hash.update(record.exec.as_str().as_bytes());
    hash.update(record.sequence.to_le_bytes());
    hash.update(record.timestamp_unix_ms.to_le_bytes());
    hash.update([stream_code(record.stream)]);
    hash.update(record.flags.to_le_bytes());
    hash.update((record.payload.len() as u64).to_le_bytes());
    hash.update(&record.payload);
    hash.finalize().into()
}

type Sha256Digest = sha2::digest::Output<Sha256>;

pub(super) fn decode_record(
    row: &rusqlite::Row<'_>,
    expected_exec: &ExecId,
) -> Result<OutputRecord> {
    let sequence: u64 = row.get(0)?;
    let timestamp: u64 = row.get(1)?;
    let stream = stream_from_code(row.get::<_, u8>(2)?)?;
    let flags: u16 = row.get(3)?;
    let payload: Vec<u8> = row.get(4)?;
    let digest: Vec<u8> = row.get(5)?;
    let record = OutputRecord {
        exec: expected_exec.clone(),
        stream,
        sequence,
        timestamp_unix_ms: timestamp,
        flags,
        payload,
    };
    if digest.as_slice() != record_digest(&record).as_slice() {
        return Err(Error::State);
    }
    Ok(record)
}
