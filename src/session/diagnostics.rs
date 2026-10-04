//! Startup audit for persistent diagnostics owned by durable session reservations.
use crate::{
    error::{Error, Result},
    state::diagnostics_quota::DiagnosticReservation,
};
use std::{collections::HashMap, fs, os::unix::fs::MetadataExt, path::Path};

/// Audits the diagnostics namespace before recovery can release any durable
/// reservation. Each file is checked against half its session's reservation.
pub(crate) fn scan(operator_root: &Path, reservations: &[DiagnosticReservation]) -> Result<()> {
    let mut by_session = HashMap::new();
    let mut reserved_total = 0_u64;
    for reservation in reservations {
        if reservation.session_id.is_empty()
            || reservation.session_id.contains('/')
            || reservation.reserved_bytes == 0
            || reservation.reserved_bytes % 2 != 0
            || by_session
                .insert(reservation.session_id.as_str(), reservation)
                .is_some()
        {
            return Err(Error::State);
        }
        reserved_total = reserved_total
            .checked_add(reservation.reserved_bytes)
            .ok_or(Error::State)?;
    }

    let root = operator_root.join("firecracker");
    let root_metadata = match fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(Error::Path);
    }

    let mut actual_total = 0_u64;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(Error::Path)?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::Path);
        }
        let reservation = by_session.get(name).copied();
        let per_file_limit = reservation.map_or(0, |item| item.reserved_bytes / 2);
        let stderr = diagnostic_file(
            &entry.path(),
            &["jailer.stderr"],
            rustix::process::geteuid().as_raw(),
            per_file_limit,
        )?;
        let serial = diagnostic_file(
            &entry.path(),
            &["root", "run", "serial.log"],
            reservation.map_or(u32::MAX, |item| item.session_uid),
            per_file_limit,
        )?;
        let session_actual = stderr
            .unwrap_or(0)
            .checked_add(serial.unwrap_or(0))
            .ok_or(Error::State)?;
        if reservation.is_none() && (stderr.is_some() || serial.is_some()) {
            return Err(Error::Path);
        }
        if let Some(reservation) = reservation {
            if session_actual > reservation.reserved_bytes {
                return Err(Error::Path);
            }
        }
        actual_total = actual_total
            .checked_add(session_actual)
            .ok_or(Error::State)?;
    }
    if actual_total > reserved_total {
        return Err(Error::State);
    }
    Ok(())
}

fn diagnostic_file(
    session: &Path,
    components: &[&str],
    expected_uid: u32,
    limit: u64,
) -> Result<Option<u64>> {
    let (file_name, parents) = components.split_last().ok_or(Error::State)?;
    let mut parent = session.to_path_buf();
    for component in parents {
        parent.push(component);
        let metadata = match fs::symlink_metadata(&parent) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::Path);
        }
    }
    let path = parent.join(file_name);
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.uid() != expected_uid
        || metadata.len() > limit
    {
        return Err(Error::Path);
    }
    Ok(Some(metadata.len()))
}

#[cfg(test)]
mod tests {
    use super::scan;
    use crate::state::diagnostics_quota::DiagnosticReservation;
    use std::fs;

    fn reservation(session_id: &str) -> DiagnosticReservation {
        DiagnosticReservation {
            session_id: session_id.into(),
            session_uid: rustix::process::geteuid().as_raw(),
            reserved_bytes: 20,
        }
    }

    #[test]
    fn startup_scan_accepts_reserved_files_and_rejects_stale_or_excess_files() {
        let directory = tempfile::tempdir().unwrap();
        let diagnostics = directory.path().join("firecracker");
        let session = diagnostics.join("session-a");
        fs::create_dir_all(session.join("root/run")).unwrap();
        fs::write(session.join("jailer.stderr"), b"ok").unwrap();
        fs::write(session.join("root/run/serial.log"), b"serial").unwrap();
        let reservations = [reservation("session-a")];
        scan(directory.path(), &reservations).unwrap();

        fs::write(session.join("root/run/serial.log"), [0; 11]).unwrap();
        assert!(scan(directory.path(), &reservations).is_err());
        fs::remove_dir_all(&diagnostics).unwrap();
        let stale = diagnostics.join("stale");
        fs::create_dir_all(&stale).unwrap();
        fs::write(stale.join("jailer.stderr"), b"orphan").unwrap();
        assert!(scan(directory.path(), &reservations).is_err());
    }
}
