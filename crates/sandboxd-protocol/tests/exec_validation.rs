use sandboxd_protocol::ExecId;
use sandboxd_protocol::exec::{ExecutionSpec, OutputPolicy, StdinMode};
use std::collections::BTreeMap;

#[test]
fn image_defaults_accept_empty_argv_without_panicking_but_reject_empty_executable() {
    let mut spec = ExecutionSpec {
        id: ExecId::new("image-defaults").unwrap(),
        argv: Vec::new(),
        use_image_defaults: true,
        cwd: "/".into(),
        uid: 0,
        gid: 0,
        supplementary_groups: Vec::new(),
        readonly_root: false,
        mounts: Vec::new(),
        max_processes: 64,
        environment: BTreeMap::new(),
        secret_environment: BTreeMap::new(),
        pty: None,
        stdin: StdinMode::Closed,
        timeout_ms: 1000,
        detached: false,
        output_policy: OutputPolicy::Disabled,
        output_bytes: 0,
    };
    assert!(spec.validate().is_ok());
    spec.use_image_defaults = false;
    assert!(spec.validate().is_err());
    spec.use_image_defaults = true;
    spec.argv = vec![String::new()];
    assert!(spec.validate().is_err());
    spec.argv = vec!["/bin/true".into()];
    assert!(spec.validate().is_ok());
    // Supplementary groups are kernel identities, with a bounded wire budget.
    spec.supplementary_groups = vec![100, 200];
    assert!(spec.validate().is_ok());
    spec.supplementary_groups = vec![u32::MAX];
    assert!(spec.validate().is_err());
    spec.supplementary_groups = vec![100; 33];
    assert!(spec.validate().is_err());
    spec.supplementary_groups.clear();
    use sandboxd_protocol::{VolumeId, exec::ExecutionMount};
    spec.mounts = vec![
        ExecutionMount::Volume {
            volume_id: VolumeId::new("disk-a").unwrap(),
            target: "/cache".into(),
            readonly: false,
        },
        ExecutionMount::Volume {
            volume_id: VolumeId::new("disk-b").unwrap(),
            target: "/cache".into(),
            readonly: true,
        },
    ];
    assert!(
        spec.validate().is_err(),
        "different disks must not collide at one target"
    );
    if let ExecutionMount::Volume { target, .. } = &mut spec.mounts[1] {
        *target = "/other".into();
    }
    assert!(spec.validate().is_ok());
    spec.uid = u32::MAX;
    assert!(spec.validate().is_err());
}

#[test]
fn tmpfs_mounts_are_bounded_and_cannot_replace_guest_control_mounts() {
    use sandboxd_protocol::exec::ExecutionMount;
    for target in ["/scratch", "/workspace/tmp"] {
        assert!(
            ExecutionMount::Tmpfs {
                target: target.into(),
                size_bytes: 4096,
                readonly: false
            }
            .validate()
            .is_ok()
        );
    }
    for target in [
        "/",
        "relative",
        "/x/../escape",
        "/x/./y",
        "/x/",
        "/proc",
        "/proc/self",
        "/dev/x",
        "/sys/x",
    ] {
        assert!(
            ExecutionMount::Tmpfs {
                target: target.into(),
                size_bytes: 4096,
                readonly: false
            }
            .validate()
            .is_err(),
            "{target}"
        );
    }
    for size_bytes in [0, (1 << 30) + 1] {
        assert!(
            ExecutionMount::Tmpfs {
                target: "/scratch".into(),
                size_bytes,
                readonly: true
            }
            .validate()
            .is_err()
        );
    }
}

#[test]
fn binary_secret_mount_wire_redacts_diagnostics_and_rejects_unsafe_policy() {
    use sandboxd_protocol::exec::{ExecutionMount, SecretBytes};
    let mut secret = ExecutionMount::Secret {
        target: "/run/secrets/token".into(),
        value: SecretBytes(vec![0, 255, 7]),
        uid: 1000,
        gid: 1000,
        mode: 0o400,
    };
    assert!(secret.validate().is_ok());
    assert!(!format!("{secret:?}").contains("255"));
    let mut encoded = Vec::new();
    ciborium::into_writer(&secret, &mut encoded).unwrap();
    let decoded: ExecutionMount = ciborium::from_reader(encoded.as_slice()).unwrap();
    assert_eq!(decoded, secret);
    if let ExecutionMount::Secret { mode, .. } = &mut secret {
        *mode = 0o4755;
    }
    assert!(secret.validate().is_err());
    if let ExecutionMount::Secret { mode, value, .. } = &mut secret {
        *mode = 0o400;
        value.0 = vec![1; 65537];
    }
    assert!(secret.validate().is_err());
}
