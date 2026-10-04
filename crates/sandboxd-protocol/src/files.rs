use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileMetadata {
    pub kind: FileKind,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub modified_unix_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    #[default]
    Other,
    Regular,
    Directory,
    Symlink,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryEntry {
    pub name: String,
    pub metadata: FileMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum FileRequest {
    Stat {
        path: String,
        follow_symlink: bool,
    },
    List {
        path: String,
        cursor: Option<String>,
        limit: u16,
    },
    Read {
        path: String,
        offset: u64,
        limit: u32,
    },
    Write {
        transfer_id: String,
        path: String,
        offset: u64,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        final_chunk: bool,
        sha256: Option<[u8; 32]>,
        atomic_replace: bool,
    },
    Mkdir {
        path: String,
        mode: u32,
        parents: bool,
    },
    Remove {
        path: String,
        recursive: bool,
    },
    Rename {
        source: String,
        destination: String,
    },
    Chmod {
        path: String,
        mode: u32,
    },
    Chown {
        path: String,
        uid: u32,
        gid: u32,
    },
    Symlink {
        target: String,
        path: String,
    },
    Readlink {
        path: String,
    },
}
impl FileRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        let paths: Vec<&str> = match self {
            Self::Rename {
                source,
                destination,
            } => vec![source, destination],
            Self::Symlink { target, path } => vec![target, path],
            Self::Stat { path, .. }
            | Self::List { path, .. }
            | Self::Read { path, .. }
            | Self::Write { path, .. }
            | Self::Mkdir { path, .. }
            | Self::Remove { path, .. }
            | Self::Chmod { path, .. }
            | Self::Chown { path, .. }
            | Self::Readlink { path } => vec![path],
        };
        if paths
            .iter()
            .any(|p| p.is_empty() || p.len() > 4096 || p.contains('\0'))
        {
            return Err("invalid guest path");
        }
        match self {
            Self::List { limit, cursor, .. }
                if *limit == 0
                    || *limit > 256
                    || cursor.as_ref().is_some_and(|v| {
                        v.is_empty() || v.len() > 4096 || v.contains('\0') || v.contains('/')
                    }) =>
            {
                Err("directory page limit")
            }
            Self::Read { limit, offset, .. }
                if *limit == 0
                    || *limit as usize > crate::MAX_DATA_BYTES
                    || offset.checked_add(u64::from(*limit)).is_none() =>
            {
                Err("read limit")
            }
            Self::Write {
                data,
                offset,
                transfer_id,
                ..
            } if data.len() > crate::MAX_DATA_BYTES
                || offset.checked_add(data.len() as u64).is_none()
                || crate::OperationId::new(transfer_id.as_str()).is_err() =>
            {
                Err("write limit")
            }
            Self::Mkdir { mode, .. } | Self::Chmod { mode, .. } if *mode > 0o7777 => {
                Err("file mode limit")
            }
            _ => Ok(()),
        }
    }
}
