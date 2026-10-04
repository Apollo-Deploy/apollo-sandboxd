use crate::{Result, Target};
use clap::Subcommand;
use sandboxd_protocol::{CheckpointCommand, CheckpointId, Request};
#[derive(Subcommand)]
pub enum CheckpointCommandLine {
    /// Quiesce and checkpoint the current writable filesystem.
    FilesystemCreate { id: CheckpointId },
    /// Atomically restore a checkpoint while compute is stopped.
    FilesystemRestore { id: CheckpointId },
    /// Delete an owned checkpoint and release its storage reservation.
    Delete { id: CheckpointId },
}
pub(crate) fn request(target: Target, command: CheckpointCommandLine) -> Result<Request> {
    let fence = target.fence()?;
    let command = match command {
        CheckpointCommandLine::FilesystemCreate { id } => CheckpointCommand::Create { id, fence },
        CheckpointCommandLine::FilesystemRestore { id } => CheckpointCommand::Restore { id, fence },
        CheckpointCommandLine::Delete { id } => CheckpointCommand::Delete { id, fence },
    };
    Ok(Request::Checkpoint {
        operation: target.canonical_operation()?,
        operation_sequence: target.operation_sequence,
        command: Box::new(command),
    })
}
