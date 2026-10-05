//! Native lock lifetime proof, including daemon death and verified cleanup.
use super::*;

async fn start(
    socket: &Path,
    record: &Sandbox,
    label: &str,
) -> Result<Response, apollo_sandboxd::error::Error> {
    let sequence = OP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    client::call(
        socket,
        &Request::Mutate {
            operation: OperationId::with_sequence(sequence, label).unwrap(),
            operation_sequence: sequence,
            mutation: Box::new(Mutation::Session {
                fence: fence(record),
                control: SessionControl::Start,
            }),
        },
        Duration::from_secs(120),
    )
    .await
}
async fn inspect(socket: &Path, id: &SandboxId) -> Sandbox {
    let Response::Sandbox(record) = client::call(
        socket,
        &Request::Inspect {
            sandbox: id.clone(),
        },
        Duration::from_secs(10),
    )
    .await
    .unwrap() else {
        panic!("sandbox")
    };
    *record
}
fn assert_locked(path: &Path) {
    let file = std::fs::File::open(path).expect("private backing");
    assert!(
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).is_err(),
        "active VMM lost its exclusive backing lock after startup"
    );
}
async fn stop(socket: &Path, record: &Sandbox, label: &str) -> Sandbox {
    call(
        socket,
        label,
        Mutation::Session {
            fence: fence(record),
            control: SessionControl::Stop,
        },
    )
    .await;
    inspect_until(socket, &record.id, |s| s == SandboxState::Stopped).await
}
pub(super) async fn qualify(
    socket: &Path,
    daemon: &mut Child,
    binary: &Path,
    config: &Path,
    log: &Path,
    evidence: &mut impl Write,
) {
    stage(evidence, "volume_allocate");
    let sequence = OP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let allocate_sequence = sequence;
    let operation = OperationId::with_sequence(sequence, "native-volume-allocate").unwrap();
    let response = client::call(
        socket,
        &Request::Volume {
            operation: operation.clone(),
            operation_sequence: sequence,
            command: Box::new(VolumeCommand::Allocate {
                size_bytes: 16 << 20,
                writable: true,
            }),
        },
        Duration::from_secs(120),
    )
    .await
    .expect("allocate volume");
    let info = match response {
        Response::Volume(info) => info,
        Response::VolumePending { .. } => {
            let deadline = Instant::now() + Duration::from_secs(120);
            loop {
                let Response::OperationReceipt(receipt) = client::call(
                    socket,
                    &Request::OperationInspect {
                        operation: operation.clone(),
                        operation_sequence: sequence,
                    },
                    Duration::from_secs(10),
                )
                .await
                .unwrap() else {
                    panic!("receipt")
                };
                if let Some(response) = receipt.response
                    && let Response::Volume(info) = *response
                {
                    break info;
                }
                assert!(Instant::now() < deadline, "volume receipt did not settle");
                sleep(Duration::from_millis(100)).await;
            }
        }
        other => panic!("allocate response: {other:?}"),
    };
    let directory = apollo_sandboxd::config::Config::load(config)
        .unwrap()
        .execution
        .unwrap()
        .drive_directory;
    let backing_path = directory
        .join("dynamic-volumes")
        .join(format!("{}.img", info.backing.id));
    let mut spec = sandbox_spec();
    spec.volumes.push(Volume {
        id: VolumeId::new("cache").unwrap(),
        catalog_key: String::new(),
        backing: Some(info.backing.clone()),
        read_only: false,
        guest_mount_point: "/cache".into(),
        filesystem: "ext4".into(),
        rate_limiter: None,
    });
    let first_id = SandboxId::new(unique("volume-first")).unwrap();
    let second_id = SandboxId::new(unique("volume-second")).unwrap();
    let Response::Sandbox(first) = call(
        socket,
        "volume-create-first",
        Mutation::Create {
            sandbox: first_id.clone(),
            expected_generation: None,
            spec: Box::new(spec.clone()),
            lease_seconds: 600,
        },
    )
    .await
    else {
        panic!("create")
    };
    let Response::Sandbox(second) = call(
        socket,
        "volume-create-second",
        Mutation::Create {
            sandbox: second_id.clone(),
            expected_generation: None,
            spec: Box::new(spec),
            lease_seconds: 600,
        },
    )
    .await
    else {
        panic!("create")
    };
    start(socket, &first, "volume-start-first")
        .await
        .expect("first start");
    let _first = inspect_until(socket, &first_id, |s| {
        matches!(s, SandboxState::GuestReady | SandboxState::Running)
    })
    .await;
    // Direct flock is independent of the new durable admission guard. This
    // fails if startup dropped BootArtifacts handles before LiveVm ownership.
    assert_locked(&backing_path);
    stage(evidence, "volume_active_lock_retained");
    assert!(
        start(socket, &second, "volume-conflicting-start")
            .await
            .is_err()
    );
    stage(evidence, "volume_second_writable_rejected");
    daemon.kill().expect("kill daemon");
    daemon.wait().unwrap();
    *daemon = start_daemon(binary, config, log);
    wait_socket(socket, daemon).await;
    initialize_operation_sequence(socket).await;
    let first = inspect_until(socket, &first_id, |s| {
        matches!(s, SandboxState::GuestReady | SandboxState::Running)
    })
    .await;
    assert_locked(&backing_path);
    stage(evidence, "volume_recovered_lock_retained");
    let second = inspect(socket, &second_id).await;
    assert!(
        start(socket, &second, "volume-conflicting-recovered-start")
            .await
            .is_err()
    );
    stage(evidence, "volume_recovered_second_writable_rejected");
    // A pre-admission rejection does not consume its durable operation sequence.
    initialize_operation_sequence(socket).await;
    stop(socket, &first, "volume-stop-first").await;
    let probe = std::fs::File::open(&backing_path).unwrap();
    rustix::fs::flock(&probe, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .expect("lock released after verified stop");
    drop(probe);
    stage(evidence, "volume_lock_released_after_stop");
    let second = inspect(socket, &second_id).await;
    start(socket, &second, "volume-start-second")
        .await
        .expect("reuse after verified stop");
    let second = inspect_until(socket, &second_id, |s| {
        matches!(s, SandboxState::GuestReady | SandboxState::Running)
    })
    .await;
    assert_locked(&backing_path);
    stop(socket, &second, "volume-stop-second").await;
    stage(evidence, "volume_reused_after_verified_cleanup");
    let sequence = OP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let response = client::call(
        socket,
        &Request::VolumeRelease {
            operation: OperationId::with_sequence(sequence, "volume-release").unwrap(),
            operation_sequence: sequence,
            backing: info.backing.clone(),
        },
        Duration::from_secs(30),
    )
    .await
    .unwrap();
    assert_eq!(
        response,
        Response::VolumeReleased {
            backing: info.backing.clone()
        }
    );
    assert!(
        !backing_path.exists(),
        "settled release must delete unpinned backing"
    );
    stage(evidence, "volume_released_after_verified_cleanup");
    let historical = client::call(
        socket,
        &Request::Volume {
            operation,
            operation_sequence: allocate_sequence,
            command: Box::new(VolumeCommand::Allocate {
                size_bytes: 16 << 20,
                writable: true,
            }),
        },
        Duration::from_secs(30),
    )
    .await
    .unwrap();
    assert_eq!(historical, Response::Volume(info));
    assert!(
        !backing_path.exists(),
        "historical replay must not recreate released backing"
    );
    stage(
        evidence,
        "volume_historical_replay_preserved_without_resurrection",
    );
}
