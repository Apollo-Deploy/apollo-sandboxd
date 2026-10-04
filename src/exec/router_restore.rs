//! Restore journal identities before accepting any new guest events.
use super::router::ExecManifest;
use super::{ExecEventRouter, OutputJournal};
use crate::{error::Result, security::path::SecureDir};
use sandboxd_protocol::codec;
use serde::Deserialize;
use std::{fs, path::Path};
const MANIFEST: &str = "exec.manifest";
const MAX_RESTORED_EXECS: usize = 256;
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExitManifest {
    exit_code: Option<i32>,
    signal: Option<u8>,
    timed_out: bool,
}

impl ExecEventRouter {
    /// Restores all immutable exec identities before subscribing to guest
    /// events. Corrupt or foreign metadata fails recovery closed.
    pub fn restore(root: &Path) -> Result<Self> {
        let router = Self::new(root)?;
        let mut count = 0usize;
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            count = count.checked_add(1).ok_or(crate::error::Error::State)?;
            if count > MAX_RESTORED_EXECS {
                return Err(crate::error::Error::Config(
                    "execution journal quota exhausted",
                ));
            }
            let path = entry.path();
            let bytes = fs::read(path.join(MANIFEST))?;
            let manifest: ExecManifest = codec::decode_body(&bytes)?;
            if entry.file_name().to_string_lossy() != manifest.exec.as_str() {
                return Err(crate::error::Error::Path);
            }
            let max_bytes = rusqlite::Connection::open_with_flags(
                path.join("journal.sqlite3"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?
            .query_row("SELECT max_bytes FROM journal_meta", [], |row| {
                row.get::<_, u64>(0)
            })?;
            let journal = OutputJournal::open(&path, manifest.exec.clone(), max_bytes)?;
            let directory = SecureDir::open(&path)?;
            let exit = match directory.open_file("exit.cbor", false) {
                Ok(mut file) => {
                    use std::io::Read;
                    if file.metadata()?.len() > 1024 {
                        return Err(crate::error::Error::State);
                    }
                    let mut bytes = Vec::new();
                    file.read_to_end(&mut bytes)?;
                    Some(codec::decode_body::<ExitManifest>(&bytes)?)
                }
                Err(crate::error::Error::Kernel(rustix::io::Errno::NOENT)) => None,
                Err(error) => return Err(error),
            };
            let mut bridge = router
                .bridge
                .lock()
                .map_err(|_| crate::error::Error::State)?;
            if let Some(exit) = exit {
                bridge.register_completed(
                    manifest.exec,
                    journal,
                    exit.exit_code,
                    exit.signal,
                    exit.timed_out,
                )?;
            } else {
                bridge.register(
                    manifest.exec.clone(),
                    journal,
                    None,
                    None,
                    manifest.output_policy,
                )?;
                bridge.restore_transport_gap(&manifest.exec)?;
            }
        }
        Ok(router)
    }
}
