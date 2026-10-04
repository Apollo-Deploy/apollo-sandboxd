//! Construct the trusted guest identity arguments independently of image data.
use crate::{
    error::{Error, Result},
    state::LaunchIntent,
};
use guest_protocol::{BootNonce, GUEST_PROTOCOL_VERSION, SessionIdentity};

pub(crate) fn identity(intent: &LaunchIntent) -> SessionIdentity {
    SessionIdentity {
        sandbox: intent.key.sandbox.clone(),
        sandbox_generation: intent.key.sandbox_generation,
        session: intent.key.session.clone(),
        session_generation: intent.key.generation,
        boot_nonce: BootNonce(intent.boot_nonce),
        vsock_cid: intent.cid,
        protocol_version: GUEST_PROTOCOL_VERSION,
    }
}

pub(crate) fn boot_arguments(template: &str, intent: &LaunchIntent) -> Result<String> {
    validate_template(template)?;
    let value = format!(
        "{} sandboxd.sandbox={} sandboxd.sandbox-generation={} sandboxd.session={} sandboxd.session-generation={} sandboxd.boot-nonce={} sandboxd.vsock-cid={}",
        template.trim(),
        intent.key.sandbox,
        intent.key.sandbox_generation.get(),
        intent.key.session,
        intent.key.generation.get(),
        hex::encode(intent.boot_nonce),
        intent.cid,
    );
    if value.len() >= 2048 {
        return Err(Error::Config(
            "guest kernel arguments exceed architecture limit",
        ));
    }
    Ok(value)
}

pub(crate) fn validate_template(template: &str) -> Result<()> {
    // Keep below the x86 Linux command-line limit including its terminator.
    // Quotes or escapes could make the appended identity part of another value.
    if template.len() > 1024
        || template
            .chars()
            .any(|c| c.is_control() || matches!(c, '\'' | '"' | '\\'))
        || template
            .split_whitespace()
            .any(|arg| arg.starts_with("sandboxd."))
    {
        return Err(Error::Config("unsafe guest kernel argument template"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{SessionKey, SessionPins};
    use sandboxd_protocol::*;

    fn intent() -> LaunchIntent {
        LaunchIntent {
            key: SessionKey {
                sandbox: SandboxId::new("arguments-sandbox").unwrap(),
                sandbox_generation: SandboxGeneration::new(3).unwrap(),
                session: SessionId::new("arguments-session").unwrap(),
                generation: SessionGeneration::new(7).unwrap(),
            },
            state: SessionState::JailerStarting,
            uid: 200000,
            gid: 200000,
            cid: 19,
            boot_nonce: [0x5a; 32],
            has_received_secrets: false,
            host_boot_id: "00000000-0000-0000-0000-000000000000".into(),
            pins: SessionPins {
                architecture: Architecture::X86_64,
                runtime_profile: "runtime".into(),
                runtime_version: "1.17.0".into(),
                firecracker_sha256: "a".repeat(64),
                jailer_sha256: "b".repeat(64),
                kernel_profile: "kernel".into(),
                kernel_sha256: "c".repeat(64),
                initramfs_sha256: "d".repeat(64),
                base_image: ImageDigest::new(format!("sha256:{}", "e".repeat(64))).unwrap(),
                volumes: Vec::new(),
            },
        }
    }

    #[test]
    fn boot_arguments_bind_the_complete_current_session() {
        let intent = intent();
        let args = boot_arguments("console=ttyS0 pci=off", &intent).unwrap();
        for field in [
            "sandbox=arguments-sandbox",
            "sandbox-generation=3",
            "session=arguments-session",
            "session-generation=7",
            "vsock-cid=19",
        ] {
            assert!(
                args.split_whitespace()
                    .any(|arg| arg == format!("sandboxd.{field}"))
            );
        }
        assert!(args.contains(&format!("sandboxd.boot-nonce={}", "5a".repeat(32))));
        for unsafe_template in ["sandboxd.session=old", "console=\"ttyS0", "a\\b", "a\nb"] {
            assert!(boot_arguments(unsafe_template, &intent).is_err());
        }
        assert!(boot_arguments(&"x".repeat(1025), &intent).is_err());
        assert_eq!(identity(&intent).session_generation, intent.key.generation);
    }
}
