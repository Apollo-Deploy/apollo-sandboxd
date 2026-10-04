//! The immutable start body fences replay; later controls have their own operation digests.
use crate::{
    error::{Error, Result},
    exec::ExecEventRouter,
};
use sandboxd_protocol::{ExecId, GuestCommand};
use std::path::Path;
/// Called only after the current fenced VM's router confirms this exec exists.
pub(super) fn validate_existing(
    root: &Path,
    exec: &ExecId,
    command: &GuestCommand,
    digest: [u8; 32],
) -> Result<()> {
    if matches!(command, GuestCommand::ExecStart { .. })
        && !ExecEventRouter::manifest_matches(root, exec, digest)?
    {
        return Err(Error::State);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use sandboxd_protocol::exec::{ExecutionSpec, OutputPolicy, StdinMode};
    #[test]
    fn existing_exec_controls_do_not_reuse_the_start_operation_digest() {
        let directory = tempfile::tempdir().unwrap();
        let exec: ExecId = "saved".parse().unwrap();
        let command = GuestCommand::ExecStart {
            spec: Box::new(ExecutionSpec {
                id: exec.clone(),
                argv: vec!["/bin/sleep".into(), "60".into()],
                use_image_defaults: false,
                cwd: "/".into(),
                uid: 0,
                gid: 0,
                environment: Default::default(),
                secret_environment: Default::default(),
                pty: None,
                stdin: StdinMode::Closed,
                timeout_ms: 60000,
                detached: true,
                output_policy: OutputPolicy::Disabled,
            }),
        };
        let start_digest = [1; 32];
        let control_digest = [2; 32];
        ExecEventRouter::prepare_manifest(
            &directory.path().join(exec.as_str()),
            &exec,
            start_digest,
            OutputPolicy::Disabled,
        )
        .unwrap();
        validate_existing(directory.path(), &exec, &command, start_digest).unwrap();
        assert!(validate_existing(directory.path(), &exec, &command, control_digest).is_err());
        for control in [
            GuestCommand::ExecWait { exec: exec.clone() },
            GuestCommand::ExecSignal {
                exec: exec.clone(),
                signal: 15,
            },
            GuestCommand::ExecCancel { exec: exec.clone() },
        ] {
            validate_existing(directory.path(), &exec, &control, control_digest).unwrap();
        }
    }
}
