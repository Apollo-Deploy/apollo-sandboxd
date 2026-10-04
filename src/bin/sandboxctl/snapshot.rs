use crate::{Result, Target};
use clap::Subcommand;
use sandboxd_protocol::{Request, SnapshotCommand, SnapshotId, SnapshotSecretPolicy};
#[derive(Subcommand)]
pub enum SnapshotCommandLine {
    Inspect {
        snapshot: SnapshotId,
    },
    List {
        sandbox: sandboxd_protocol::SandboxId,
        #[arg(long)]
        after: Option<SnapshotId>,
        #[arg(long, default_value_t = 64)]
        limit: u16,
    },
    /// Capture encrypted full VM state and its exact filesystem.
    Create {
        snapshot: SnapshotId,
        #[command(flatten)]
        target: Target,
        #[arg(long)]
        allow_encrypted_secrets: bool,
    },
    /// Capture full VM state, then terminate compute while retaining its CID.
    Suspend {
        snapshot: SnapshotId,
        #[command(flatten)]
        target: Target,
        #[arg(long)]
        allow_encrypted_secrets: bool,
    },
    /// Restore into a fresh session; existing network connections do not survive.
    Restore {
        snapshot: SnapshotId,
        #[command(flatten)]
        target: Target,
    },
    Delete {
        snapshot: SnapshotId,
        #[command(flatten)]
        target: Target,
    },
}
pub(crate) fn request(command: SnapshotCommandLine) -> Result<Request> {
    let policy = |allow| {
        if allow {
            SnapshotSecretPolicy::AllowEncrypted
        } else {
            SnapshotSecretPolicy::Reject
        }
    };
    let (target, command) = match command {
        SnapshotCommandLine::Inspect { snapshot: id } => {
            return Ok(Request::SnapshotInspect { id });
        }
        SnapshotCommandLine::List {
            sandbox,
            after,
            limit,
        } => {
            return Ok(Request::SnapshotList {
                sandbox,
                after,
                limit,
            });
        }
        SnapshotCommandLine::Create {
            snapshot: id,
            allow_encrypted_secrets,
            target,
        } => {
            let fence = target.fence()?;
            (
                target,
                SnapshotCommand::Create {
                    id,
                    fence,
                    secret_policy: policy(allow_encrypted_secrets),
                },
            )
        }
        SnapshotCommandLine::Suspend {
            snapshot: id,
            allow_encrypted_secrets,
            target,
        } => {
            let fence = target.fence()?;
            (
                target,
                SnapshotCommand::Suspend {
                    id,
                    fence,
                    secret_policy: policy(allow_encrypted_secrets),
                },
            )
        }
        SnapshotCommandLine::Restore {
            snapshot: id,
            target,
        } => {
            let fence = target.fence()?;
            (target, SnapshotCommand::Restore { id, fence })
        }
        SnapshotCommandLine::Delete {
            snapshot: id,
            target,
        } => {
            let fence = target.fence()?;
            (target, SnapshotCommand::Delete { id, fence })
        }
    };
    Ok(Request::Snapshot {
        operation: target.canonical_operation()?,
        operation_sequence: target.operation_sequence,
        command: Box::new(command),
    })
}
