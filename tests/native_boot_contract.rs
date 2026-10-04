//! Real x86_64 Firecracker qualification.
//!
//! This ignored test is run by the bounded native qualification runner as root
//! on the pinned Linux host. Once explicitly selected, every missing input is
//! a failure.

use apollo_sandboxd::{
    config::Config,
    jailer::{CgroupLimits, CgroupV2, JailInputs, JailStage},
    runtime::{VerifiedCatalogs, verify},
    session::{AssetInputs, BootInputs, LaunchInputs, boot, stop_and_cleanup},
    state::{SessionPreparation, Store, StoreLaunchJournal},
    storage::{DriveFactory, DriveOwner},
};
use guest_protocol::{
    ExecutionSpec, FileRequest, GuestMessage, OutputPolicy, StdinMode, TerminalSize,
};
use sandboxd_protocol::*;
use std::{
    collections::BTreeMap,
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

fn required(name: &str) -> PathBuf {
    let value = env::var_os(name).unwrap_or_else(|| panic!("{name} is required"));
    let path = PathBuf::from(value);
    assert!(path.is_absolute(), "{name} must be absolute");
    path
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .expect("host boot identity")
        .trim()
        .to_owned()
}

fn resource() -> Resources {
    Resources {
        vcpus: 1,
        memory_mib: 128,
        state_disk_mib: 64,
        host_memory_max_bytes: 268_435_456,
        cpu_quota_us: 100_000,
        cpu_period_us: 100_000,
        cpu_profile: None,
        cpuset: None,
        state_rate_limiter: None,
    }
}

fn spec(image: ImageDigest) -> SandboxSpec {
    SandboxSpec {
        architecture: Architecture::X86_64,
        image,
        kernel_profile: "amazonlinux-microvm-x86".into(),
        runtime_profile: "fc-1-17-x86".into(),
        persistence: Persistence::FilesystemPersistent,
        resources: resource(),
        network: NetworkMode::None,
        volumes: Vec::new(),
        environment: BTreeMap::new(),
        lifetimes: Lifetimes {
            sandbox_ttl_seconds: 300,
            session_max_seconds: 300,
            idle_seconds: 120,
        },
    }
}

fn assert_path(path: &Path) {
    assert!(
        path.is_absolute() && !path.to_string_lossy().contains(".."),
        "unsafe path: {path:?}"
    );
}

fn bounded_operator_log(path: &Path) -> Option<String> {
    const LIMIT: usize = 64 * 1024;
    const EDGE: usize = LIMIT / 2;
    let bytes = fs::read(path).ok()?;
    if bytes.len() <= LIMIT {
        return Some(String::from_utf8_lossy(&bytes).into_owned());
    }
    let mut detail = String::from_utf8_lossy(&bytes[..EDGE]).into_owned();
    detail.push_str("\n... <middle omitted> ...\n");
    detail.push_str(&String::from_utf8_lossy(&bytes[bytes.len() - EDGE..]));
    Some(detail)
}

struct KillVmmOnUnwind<'a>(&'a apollo_sandboxd::process::ProcessIdentity);

impl Drop for KillVmmOnUnwind<'_> {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        let _ = self.0.send_signal(rustix::process::Signal::KILL);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native Linux/KVM qualification; requires the pinned host assets and root privileges"]
async fn native_x86_firecracker_boot_exec_file_and_pty() {
    let config_path = required("APOLLO_NATIVE_CONFIG");
    let operator_root = required("APOLLO_NATIVE_OPERATOR_ROOT");
    let cgroup_parent = required("APOLLO_NATIVE_CGROUP_PARENT");
    let drive_dir = required("APOLLO_NATIVE_DRIVE_DIR");
    let base_path = required("APOLLO_NATIVE_BASE_IMAGE");
    let formatter_path = required("APOLLO_NATIVE_FORMATTER");
    for path in [
        &operator_root,
        &cgroup_parent,
        &drive_dir,
        &base_path,
        &formatter_path,
    ] {
        assert_path(path);
    }

    let config = Config::load(&config_path).expect("pinned qualification config");
    let mut catalogs = VerifiedCatalogs::load(&config)
        .await
        .expect("verified runtime and kernel catalog");
    let image = ImageDigest::new(format!(
        "sha256:{}",
        env::var("APOLLO_NATIVE_BASE_DIGEST").expect("APOLLO_NATIVE_BASE_DIGEST")
    ))
    .expect("base digest");
    let sandbox_spec = spec(image.clone());
    sandbox_spec.validate().expect("bounded qualification spec");
    let pins = catalogs.session_pins(&sandbox_spec).expect("catalog pins");

    let state_parent = required("APOLLO_NATIVE_STATE_DIR");
    let state_path = state_parent.join(format!("run-{}", std::process::id()));
    fs::create_dir(&state_path).expect("private durable state directory");
    fs::set_permissions(&state_path, fs::Permissions::from_mode(0o700)).expect("state permissions");
    let mut store = Store::open(
        &state_path,
        config.quotas.clone(),
        config.leases.clone(),
        config.state.event_retention,
    )
    .expect("durable store");
    let owner = 0u32;
    let sandbox_id = SandboxId::new("native-qualification").expect("sandbox id");
    let response = store
        .mutate(
            owner,
            &OperationId::new("native-create").unwrap(),
            &Mutation::Create {
                sandbox: sandbox_id,
                expected_generation: None,
                spec: Box::new(sandbox_spec),
                lease_seconds: 300,
            },
            now_ms(),
        )
        .expect("durable sandbox identity");
    let record = match response {
        Response::Sandbox(value) => *value,
        _ => panic!("sandbox create response"),
    };
    let prepared = store
        .prepare_session(
            owner,
            &OperationId::new("native-session").unwrap(),
            &Fence {
                sandbox: record.id.clone(),
                generation: record.generation,
                session_generation: record.session.as_ref().map(|s| s.generation),
                lease: record.lease.id.clone(),
            },
            SessionPreparation {
                pins: &pins,
                pools: &config.identities,
                host_boot_id: &boot_id(),
                now_ms: now_ms(),
            },
        )
        .expect("durable session intent");
    let intent = prepared.intent.expect("new session intent");
    store
        .begin_session_launch(owner, &intent.key, now_ms())
        .expect("enter jailer launch state");
    let intent = store
        .session_intent(owner, &intent.key)
        .expect("reload launch intent state");

    let formatter = verify(
        &formatter_path,
        &env::var("APOLLO_NATIVE_FORMATTER_DIGEST").expect("formatter digest"),
        true,
    )
    .expect("verified ext4 formatter");
    let drive_root = apollo_sandboxd::security::path::SecureDir::open(&drive_dir)
        .expect("private drive directory");
    let mut drives = DriveFactory::new(drive_root, formatter, 128 << 20).expect("drive factory");
    let state = drives
        .create(
            &VolumeId::new(format!("native-state-{}", std::process::id())).unwrap(),
            64 << 20,
            DriveOwner::new(intent.uid, intent.gid).unwrap(),
        )
        .expect("formatted state drive");
    let runtime = catalogs
        .runtimes
        .get_mut(&intent.pins.runtime_profile)
        .expect("runtime pin");
    let kernel = catalogs
        .kernels
        .get_mut(&intent.pins.kernel_profile)
        .expect("kernel pin");
    let base = verify(
        &base_path,
        &env::var("APOLLO_NATIVE_BASE_DIGEST").unwrap(),
        false,
    )
    .expect("verified root image");
    let assets = match apollo_sandboxd::session::StagedAssets::prepare(
        AssetInputs {
            operator_root: &operator_root,
            session_id: intent.key.session.as_str(),
            kernel: &kernel.kernel,
            initramfs: &kernel.initramfs,
            base: &base,
            state: &state.file,
            volumes: &[],
        },
        |_| Ok(()),
    ) {
        Ok(assets) => assets,
        Err(error) => {
            panic!("descriptor-pinned jail assets: {error:?}");
        }
    };
    let limits = CgroupLimits::from_resources(&resource()).expect("bounded cgroup limits");
    let cgroup = CgroupV2::prepare(&cgroup_parent, intent.key.session.as_str(), limits)
        .expect("owned cgroup leaf");
    assert_eq!(
        fs::read_to_string(cgroup.path().join("memory.max"))
            .expect("observed cgroup memory limit")
            .trim(),
        resource().host_memory_max_bytes.to_string()
    );
    assert_eq!(
        fs::read_to_string(cgroup.path().join("cpu.max"))
            .expect("observed cgroup cpu limit")
            .trim(),
        format!("{} {}", resource().cpu_quota_us, resource().cpu_period_us)
    );
    let stage = JailStage::prepare(
        &JailInputs {
            root: operator_root.clone(),
            session_id: intent.key.session.to_string(),
            uid: intent.uid,
            gid: intent.gid,
        },
        runtime,
    )
    .expect("jailer stage");
    let journal_key = intent.key.clone();
    let expected_guest = guest_protocol::SessionIdentity {
        sandbox: journal_key.sandbox.clone(),
        sandbox_generation: journal_key.sandbox_generation,
        session: journal_key.session.clone(),
        session_generation: journal_key.generation,
        boot_nonce: guest_protocol::BootNonce(intent.boot_nonce),
        vsock_cid: intent.cid,
        protocol_version: guest_protocol::GUEST_PROTOCOL_VERSION,
    };
    let mut journal = StoreLaunchJournal::new(&mut store, owner, &journal_key);
    let result = boot(
        BootInputs {
            restore_identity: None,
            launch: LaunchInputs {
                restore: false,
                intent: &intent,
                runtime,
                kernel,
                stage,
                cgroup,
                assets: &assets,
                resources: resource(),
                network: NetworkMode::None,
                volumes: Vec::new(),
                network_namespace_root: None,
                api_socket: PathBuf::from("/run/firecracker.socket"),
                vsock_socket: PathBuf::from("/run/vsock.socket"),
                boot_args: "console=ttyS0 reboot=k panic=1 pci=off",
                timeout: Duration::from_secs(90),
            },
            expected_guest: expected_guest.clone(),
            handshake_operation: OperationId::new("native-handshake").unwrap(),
        },
        &mut journal,
    )
    .await;
    drop(journal);
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            let diagnostics = assets
                .manifest
                .root
                .parent()
                .map(|path| path.join("jailer.stderr"));
            let detail = diagnostics.and_then(|path| bounded_operator_log(&path));
            let serial = assets.manifest.root.join("run/serial.log");
            let serial_detail = bounded_operator_log(&serial);
            let cleanup = match (
                store.session_process(owner, &journal_key),
                store.session_resources(owner, &journal_key),
            ) {
                (Ok(Some(process)), Ok(Some(manifest))) => {
                    apollo_sandboxd::session::cleanup_after_recorded_exit(
                        &process,
                        &manifest,
                        &journal_key,
                    )
                    .and_then(|proof| {
                        store.record_session_stopped(owner, &journal_key, proof, now_ms())
                    })
                    .map_err(|failure| format!("{failure:?}"))
                }
                (process, manifest) => Err(format!(
                    "incomplete recovery journal: process={process:?} manifest={manifest:?}"
                )),
            };
            panic!(
                "real jailed Firecracker boot and READY: {error:?}; cleanup={cleanup:?}; jailer stderr (bounded): {detail:?}; operator serial (bounded): {serial_detail:?}"
            );
        }
    };
    let _kill_on_unwind = KillVmmOnUnwind(&result.launch.process);
    let guest = &result.guest;
    let exec = ExecId::new("native-exec").unwrap();
    let ready = guest
        .request(
            OperationId::new("native-exec-start").unwrap(),
            GuestMessage::ExecStart {
                spec: Box::new(ExecutionSpec {
                    id: exec.clone(),
                    argv: vec!["/bin/sh".into(), "-c".into(), "printf native-exec".into()],
                    use_image_defaults: false,
                    cwd: "/".into(),
                    uid: 0,
                    gid: 0,
                    environment: BTreeMap::new(),
                    secret_environment: BTreeMap::new(),
                    pty: None,
                    stdin: StdinMode::Closed,
                    timeout_ms: 10_000,
                    detached: false,
                    output_policy: OutputPolicy::Required,
                }),
            },
        )
        .await
        .expect("guest exec request");
    assert!(matches!(ready.message, GuestMessage::Ready));
    let mut output = Vec::new();
    loop {
        match guest
            .receive(Duration::from_secs(10))
            .await
            .expect("exec event")
        {
            peer if matches!(peer.message, GuestMessage::Output { .. }) => {
                if let GuestMessage::Output { record } = peer.message {
                    output.extend(record.payload);
                }
            }
            peer if matches!(peer.message, GuestMessage::ExecExit { .. }) => break,
            _ => {}
        }
    }
    assert_eq!(output, b"native-exec");
    let write = guest
        .request(
            OperationId::new("native-file-write").unwrap(),
            GuestMessage::File {
                request: FileRequest::Write {
                    transfer_id: "native-file".into(),
                    path: "/qualification.txt".into(),
                    offset: 0,
                    data: b"persistent-state".to_vec(),
                    final_chunk: true,
                    sha256: None,
                    atomic_replace: true,
                },
            },
        )
        .await
        .expect("guest file write");
    assert!(matches!(write.message, GuestMessage::FileResult { .. }));
    let read = guest
        .request(
            OperationId::new("native-file-read").unwrap(),
            GuestMessage::File {
                request: FileRequest::Read {
                    path: "/qualification.txt".into(),
                    offset: 0,
                    limit: 1024,
                },
            },
        )
        .await
        .expect("guest file read");
    match read.message {
        GuestMessage::FileResult { data, .. } => assert_eq!(data, b"persistent-state"),
        other => panic!("unexpected file response: {other:?}"),
    }
    let pty = ExecId::new("native-pty").unwrap();
    guest
        .request(
            OperationId::new("native-pty-start").unwrap(),
            GuestMessage::ExecStart {
                spec: Box::new(ExecutionSpec {
                    id: pty,
                    argv: vec!["/bin/sh".into(), "-c".into(), "printf native-pty".into()],
                    use_image_defaults: false,
                    cwd: "/".into(),
                    uid: 0,
                    gid: 0,
                    environment: BTreeMap::new(),
                    secret_environment: BTreeMap::new(),
                    pty: Some(TerminalSize {
                        rows: 24,
                        columns: 80,
                    }),
                    stdin: StdinMode::Closed,
                    timeout_ms: 10_000,
                    detached: false,
                    output_policy: OutputPolicy::Required,
                }),
            },
        )
        .await
        .expect("guest PTY start");
    let mut pty_output = Vec::new();
    loop {
        match guest
            .receive(Duration::from_secs(10))
            .await
            .expect("PTY event")
            .message
        {
            GuestMessage::Output { record } => pty_output.extend(record.payload),
            GuestMessage::ExecExit {
                exit_code,
                signal,
                timed_out,
                ..
            } => {
                assert_eq!(exit_code, Some(0));
                assert_eq!(signal, None);
                assert!(!timed_out);
                break;
            }
            _ => {}
        }
    }
    assert!(String::from_utf8_lossy(&pty_output).contains("native-pty"));
    guest
        .request(
            OperationId::new("native-shutdown").unwrap(),
            GuestMessage::Shutdown,
        )
        .await
        .expect("guest shutdown");
    drop(result.guest);
    let proof = stop_and_cleanup(
        &result.launch.process,
        &result.launch.manifest,
        &journal_key,
    )
    .await
    .expect("identity-checked native cleanup");
    store
        .record_session_stopped(owner, &journal_key, proof, now_ms())
        .expect("persist native cleanup result");
}
