//! Guest operations expose no host path or transport control authority.
use crate::{ExecId, exec::*, files::*};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestCommand {
    ExecStart {
        spec: Box<ExecutionSpec>,
    },
    ExecStdin {
        exec: ExecId,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        eof: bool,
    },
    ExecResizePty {
        exec: ExecId,
        size: TerminalSize,
    },
    ExecSignal {
        exec: ExecId,
        signal: u8,
    },
    ExecCancel {
        exec: ExecId,
    },
    ExecWait {
        exec: ExecId,
    },
    /// Replays bounded, durable output and establishes an attach cursor.
    ExecAttach {
        exec: ExecId,
        from_sequence: u64,
        limit: u16,
    },
    /// Alias with explicit replay semantics for non-interactive clients.
    ExecReplay {
        exec: ExecId,
        from_sequence: u64,
        limit: u16,
    },
    ExecList {
        after: Option<ExecId>,
        limit: u16,
    },
    File {
        request: FileRequest,
    },
    /// Host-owned operation identity for a guest upper-layer filesystem export.
    FilesystemExport {
        #[serde(default)]
        volume_id: Option<crate::VolumeId>,
        max_bytes: u64,
        max_entries: u32,
    },
}
impl GuestCommand {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::ExecStart { spec } => spec.validate(),
            Self::ExecStdin { data, .. } if data.len() > crate::MAX_DATA_BYTES => {
                Err("stdin chunk limit")
            }
            Self::ExecResizePty { size, .. }
                if size.rows == 0
                    || size.columns == 0
                    || size.rows > 4096
                    || size.columns > 4096 =>
            {
                Err("PTY size limit")
            }
            Self::ExecSignal { signal, .. } if *signal == 0 || *signal > 64 => Err("signal limit"),
            Self::ExecAttach {
                from_sequence,
                limit,
                ..
            }
            | Self::ExecReplay {
                from_sequence,
                limit,
                ..
            } if *from_sequence == 0 || *limit == 0 || *limit > 4096 => Err("output replay bounds"),
            Self::ExecList { limit, .. } if *limit == 0 || *limit > 256 => {
                Err("execution list bounds")
            }
            Self::File { request } => request.validate(),
            Self::FilesystemExport {
                volume_id: _,
                max_bytes,
                max_entries,
            } if *max_bytes == 0
                || *max_bytes > crate::MAX_FILESYSTEM_EXPORT_BYTES
                || *max_entries == 0
                || *max_entries > crate::MAX_FILESYSTEM_EXPORT_ENTRIES =>
            {
                Err("filesystem export bounds")
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestReply {
    Acknowledged,
    ExecStatus {
        exec: ExecId,
        exit: Option<ExecStatus>,
    },
    ExecExit {
        exec: ExecId,
        exit_code: Option<i32>,
        signal: Option<u8>,
        timed_out: bool,
    },
    ExecOutput(ExecOutputPage),
    ExecList {
        entries: Vec<ExecSummary>,
    },
    File {
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        offset: u64,
        eof: bool,
        metadata: Option<FileMetadata>,
        entries: Vec<DirectoryEntry>,
        link_target: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecStatus {
    pub exit_code: Option<i32>,
    pub signal: Option<u8>,
    pub timed_out: bool,
}

impl GuestReply {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::File {
                data,
                offset,
                entries,
                link_target,
                ..
            } if data.len() > crate::MAX_DATA_BYTES
                || offset.checked_add(data.len() as u64).is_none()
                || entries.len() > 256
                || entries.iter().any(|entry| {
                    entry.name.is_empty()
                        || entry.name.len() > 4096
                        || entry.name.contains(['/', '\0'])
                })
                || link_target
                    .as_ref()
                    .is_some_and(|target| target.len() > 4096 || target.contains('\0')) =>
            {
                Err("file result bounds")
            }
            Self::ExecExit {
                exit_code, signal, ..
            } if exit_code.is_some_and(|code| !(0..=255).contains(&code))
                || signal.is_some_and(|value| value == 0 || value > 64)
                || (exit_code.is_some() && signal.is_some()) =>
            {
                Err("exec exit bounds")
            }
            Self::ExecOutput(page)
                if page.items.len() > 4096
                    || page.transport_gaps.len() > 64
                    || page
                        .transport_gaps
                        .iter()
                        .any(|after| *after > page.high_watermark)
                    || page.items.iter().any(|item| match item {
                        ExecOutputItem::Record(record) => {
                            record.exec != page.exec
                                || record.sequence == 0
                                || record.payload.len() > crate::MAX_DATA_BYTES
                        }
                        ExecOutputItem::Gap {
                            from_sequence,
                            to_sequence,
                        } => *from_sequence == 0 || from_sequence > to_sequence,
                    })
                    || page
                        .items
                        .iter()
                        .filter_map(|item| match item {
                            ExecOutputItem::Record(record) => Some(record.payload.len()),
                            ExecOutputItem::Gap { .. } => None,
                        })
                        .sum::<usize>()
                        > 768 << 10 =>
            {
                Err("execution output bounds")
            }
            Self::ExecList { entries }
                if entries.len() > 256
                    || entries.iter().any(|entry| {
                        entry.exec.as_str().is_empty()
                            || entry
                                .exit_code
                                .is_some_and(|code| !(0..=255).contains(&code))
                            || entry
                                .signal
                                .is_some_and(|signal| signal == 0 || signal > 64)
                            || (entry.exit_code.is_some() && entry.signal.is_some())
                    }) =>
            {
                Err("execution list bounds")
            }
            _ => Ok(()),
        }
    }
}
