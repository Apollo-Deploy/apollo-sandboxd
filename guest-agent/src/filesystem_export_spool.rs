//! Private export spools have one guest-supervisor writer and no customer path.
use sandboxd_protocol::OperationId;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
};

pub(super) struct Spool {
    pub(super) file: File,
    state: File,
    stage: PathBuf,
    published: PathBuf,
    committed: bool,
}

impl Spool {
    pub(super) fn new(state: &File, operation: &OperationId) -> io::Result<Self> {
        recover(state)?;
        let stage = state_path(state, &format!(".export-stage-{}", operation.as_str()));
        let published = spool_path(state, operation);
        match fs::symlink_metadata(&published) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
            Ok(_) => return Err(io::Error::from(io::ErrorKind::AlreadyExists)),
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&stage)?;
        Ok(Self {
            file,
            state: state.try_clone()?,
            stage,
            published,
            committed: false,
        })
    }

    pub(super) fn publish(mut self) -> io::Result<()> {
        self.file
            .set_permissions(fs::Permissions::from_mode(0o400))?;
        self.file.sync_all()?;
        // The singleton supervisor serializes all export requests. Both names
        // are inside its trusted state FD, outside every customer namespace.
        // The destination was checked absent by this sole writer in `new`.
        fs::rename(&self.stage, &self.published)?;
        // Until directory sync succeeds, the renamed file is still owned by
        // this unacknowledged export. An error must clean the current name,
        // rather than leave a published spool that blocks the operation retry.
        self.stage = self.published.clone();
        self.state.sync_all()?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for Spool {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.stage);
            let _ = self.state.sync_all();
        }
    }
}

fn recover(state: &File) -> io::Result<()> {
    for entry in fs::read_dir(state_path(state, "."))? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(id) = name
            .to_str()
            .and_then(|name| name.strip_prefix(".export-stage-"))
        else {
            continue;
        };
        if OperationId::new(id).is_err() {
            return Err(super::path_error());
        }
        let meta = fs::symlink_metadata(entry.path())?;
        if !meta.is_file()
            || meta.uid() != 0
            || meta.nlink() != 1
            || !matches!(meta.mode() & 0o777, 0o600 | 0o400)
            || meta.len() > 1 << 30
        {
            return Err(super::path_error());
        }
        fs::remove_file(entry.path())?;
    }
    state.sync_all()
}

pub fn read(
    state: &File,
    operation: &OperationId,
    offset: u64,
    max_bytes: u32,
) -> Result<(Vec<u8>, bool), String> {
    if max_bytes == 0 || max_bytes > 60 * 1024 {
        return Err("filesystem export chunk bounds".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(spool_path(state, operation))
        .map_err(super::io_code)?;
    let meta = file.metadata().map_err(super::io_code)?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.nlink() != 1
        || meta.mode() & 0o777 != 0o400
        || meta.len() > 1 << 30
    {
        return Err("filesystem export spool identity rejected".into());
    }
    let size = meta.len();
    if offset > size {
        return Err("filesystem export offset out of range".into());
    }
    file.seek(SeekFrom::Start(offset)).map_err(super::io_code)?;
    let mut data = vec![0; (size - offset).min(u64::from(max_bytes)) as usize];
    file.read_exact(&mut data).map_err(super::io_code)?;
    let eof = offset + data.len() as u64 == size;
    Ok((data, eof))
}

pub fn retire(state: &File, operation: &OperationId) -> Result<(), String> {
    let path = spool_path(state, operation);
    match fs::symlink_metadata(&path) {
        Ok(meta) => {
            if !meta.is_file()
                || meta.uid() != 0
                || meta.nlink() != 1
                || meta.mode() & 0o777 != 0o400
                || meta.len() > 1 << 30
            {
                return Err(super::io_code(super::path_error()));
            }
            fs::remove_file(&path).map_err(super::io_code)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(super::io_code(error)),
    }
    // A prior unlink followed by a failed fsync can retry this exact receipt.
    state.sync_all().map_err(super::io_code)
}

pub(super) fn state_path(state: &File, child: &str) -> PathBuf {
    PathBuf::from(format!(
        "/proc/self/fd/{}/{}",
        std::os::fd::AsRawFd::as_raw_fd(state),
        child
    ))
}
fn spool_path(state: &File, operation: &OperationId) -> PathBuf {
    state_path(state, &format!("export-{}", operation.as_str()))
}
