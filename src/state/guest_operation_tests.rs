use super::guest_operation::*;
use super::{SessionKey, Store};
use crate::config::{IdentityPools, LeaseConfig, Quotas};
use crate::state::{SessionPins, SessionPreparation};
use rusqlite::{TransactionBehavior, params};
use sandboxd_protocol::{
    ApiError, ErrorCode, Fence, GuestCommand, OperationId, OperationReceiptState, Response, codec,
};
use sandboxd_protocol::{
    Architecture, GuestReply, ImageDigest, Lifetimes, Mutation, NetworkMode, Persistence,
    Resources, SandboxGeneration, SandboxId, SandboxSpec, SandboxState, SessionGeneration,
    SessionState,
};
use std::{os::unix::fs::PermissionsExt, path::PathBuf};

fn store() -> (tempfile::TempDir, Store) {
    let directory = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let path: PathBuf = directory.path().canonicalize().unwrap();
    let store = Store::open(
        &path,
        Quotas {
            max_active_sandboxes: 4,
            max_booting_sandboxes: 2,
            max_sandbox_identities: 8,
            max_operation_receipts: 8,
            max_vcpus: 4,
            max_memory_mib: 1024,
            max_state_disk_mib: 1024,
        },
        LeaseConfig { max_seconds: 3600 },
        20,
    )
    .unwrap();
    (directory, store)
}

fn fence() -> Fence {
    Fence {
        sandbox: SandboxId::new("guest-state").unwrap(),
        generation: SandboxGeneration::new(1).unwrap(),
        session_generation: Some(SessionGeneration::new(1).unwrap()),
        lease: "lease-1".parse().unwrap(),
    }
}

pub(super) fn active_store() -> (tempfile::TempDir, Store, Fence, GuestCommand) {
    let (directory, mut store) = store();
    let response = store
        .mutate(
            1000,
            &OperationId::new("create-guest-fixture").unwrap(),
            &Mutation::Create {
                sandbox: SandboxId::new("guest-state").unwrap(),
                expected_generation: None,
                spec: Box::new(SandboxSpec {
                    architecture: Architecture::Aarch64,
                    image: ImageDigest::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
                    kernel_profile: "reference".into(),
                    runtime_profile: "verified".into(),
                    persistence: Persistence::FilesystemPersistent,
                    resources: Resources {
                        vcpus: 1,
                        memory_mib: 128,
                        state_disk_mib: 256,
                        host_memory_max_bytes: 268_435_456,
                        cpu_quota_us: 100_000,
                        cpu_period_us: 100_000,
                        cpu_profile: None,
                        cpuset: None,
                        state_rate_limiter: None,
                    },
                    network: NetworkMode::None,
                    volumes: vec![],
                    environment: std::collections::BTreeMap::new(),
                    lifetimes: Lifetimes {
                        sandbox_ttl_seconds: 3600,
                        session_max_seconds: 1800,
                        idle_seconds: 300,
                    },
                }),
                lease_seconds: 3600,
            },
            1000,
        )
        .unwrap();
    let mut record = match response {
        Response::Sandbox(record) => *record,
        _ => panic!(),
    };
    let pins = SessionPins {
        architecture: record.spec.architecture,
        runtime_profile: record.spec.runtime_profile.clone(),
        runtime_version: "1.17.0".into(),
        firecracker_sha256: "1".repeat(64),
        jailer_sha256: "2".repeat(64),
        kernel_profile: record.spec.kernel_profile.clone(),
        kernel_sha256: "3".repeat(64),
        initramfs_sha256: "4".repeat(64),
        base_image: record.spec.image.clone(),
        volumes: Vec::new(),
    };
    let prepared = store
        .prepare_session(
            1000,
            &OperationId::new("prepare-guest-fixture").unwrap(),
            &Fence {
                sandbox: record.id.clone(),
                generation: record.generation,
                session_generation: None,
                lease: record.lease.id.clone(),
            },
            SessionPreparation {
                pins: &pins,
                pools: &IdentityPools {
                    uid_first: 200000,
                    uid_last: 200001,
                    gid_first: 300000,
                    gid_last: 300001,
                    cid_first: 3,
                    cid_last: 4,
                },
                host_boot_id: "00000000-0000-4000-8000-000000000001",
                now_ms: 1001,
            },
        )
        .unwrap();
    let mut intent = prepared.intent.unwrap();
    intent.state = SessionState::Active;
    record = store.inspect(1000, &record.id).unwrap();
    let mut session = record.session.clone().unwrap();
    session.state = SessionState::Active;
    record.session = Some(session);
    record.state = SandboxState::Running;
    let tx = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    tx.execute(
        "UPDATE sessions SET record=?1 WHERE session_id=?2",
        params![
            codec::encode_body(&intent).unwrap(),
            intent.key.session.as_str()
        ],
    )
    .unwrap();
    tx.execute(
        "UPDATE sandboxes SET record=?1 WHERE id=?2",
        params![codec::encode_body(&record).unwrap(), record.id.as_str()],
    )
    .unwrap();
    tx.commit().unwrap();
    let fence = Fence {
        sandbox: record.id,
        generation: record.generation,
        session_generation: Some(intent.key.generation),
        lease: record.lease.id,
    };
    (
        directory,
        store,
        fence,
        GuestCommand::ExecWait {
            exec: "exec-1".parse().unwrap(),
        },
    )
}

#[test]
fn completion_requires_exact_pending_digest_and_preserves_uncertain_receipt() {
    let (_directory, mut store) = store();
    let operation = OperationId::new("guest-op").unwrap();
    let pending = Response::GuestPending {
        operation: operation.clone(),
    };
    let command = GuestCommand::ExecWait {
        exec: "exec-1".parse().unwrap(),
    };
    let digest = digest(&fence(), &command).unwrap();
    store
        .connection
        .execute(
            "INSERT INTO operations(owner_uid,id,request_digest,response) VALUES (?1,?2,?3,?4)",
            params![
                1000,
                operation.as_str(),
                digest.as_slice(),
                codec::encode_body(&pending).unwrap()
            ],
        )
        .unwrap();
    let response = Response::Guest(GuestReply::Acknowledged);
    assert!(
        store
            .complete_guest_operation(1000, &operation, [9; 32], &response)
            .is_err()
    );
    let still_pending_bytes: Vec<u8> = store
        .connection
        .query_row(
            "SELECT response FROM operations WHERE owner_uid=1000 AND id='guest-op'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let still_pending: Response = codec::decode_body(&still_pending_bytes).unwrap();
    assert_eq!(still_pending, pending);
    store
        .complete_guest_operation(1000, &operation, digest, &response)
        .unwrap();
    let completed_bytes: Vec<u8> = store
        .connection
        .query_row(
            "SELECT response FROM operations WHERE owner_uid=1000 AND id='guest-op'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let completed: Response = codec::decode_body(&completed_bytes).unwrap();
    assert_eq!(completed, response);
}

#[test]
fn admission_replays_pending_and_completed_results_and_conflicts_on_body_change() {
    let (_directory, mut store, fence, command) = active_store();
    let operation = OperationId::new("guest-replay").unwrap();
    assert!(matches!(
        store
            .admit_guest_operation(1000, &operation, &fence, &command, 1100)
            .unwrap(),
        GuestAdmission::Pending(_)
    ));
    assert!(matches!(
        store
            .admit_guest_operation(1000, &operation, &fence, &command, 1101)
            .unwrap(),
        GuestAdmission::Pending(_)
    ));
    let digest = digest(&fence, &command).unwrap();
    let response = Response::Guest(GuestReply::Acknowledged);
    store
        .complete_guest_operation(1000, &operation, digest, &response)
        .unwrap();
    assert!(matches!(
        store
            .admit_guest_operation(1000, &operation, &fence, &command, 1102)
            .unwrap(),
        GuestAdmission::Complete(value) if value == response
    ));
    let changed = GuestCommand::ExecCancel {
        exec: "exec-1".parse().unwrap(),
    };
    assert!(matches!(
        store.admit_guest_operation(1000, &operation, &fence, &changed, 1102),
        Err(crate::error::Error::Api(ApiError {
            code: ErrorCode::OperationConflict,
            ..
        }))
    ));
}

#[test]
fn operation_inspection_tracks_guest_admission_and_completion() {
    let (_directory, mut store, fence, command) = active_store();
    let operation = OperationId::with_sequence(1, "guest-inspect").unwrap();
    let expected_digest = hex::encode(digest(&fence, &command).unwrap());

    assert!(matches!(
        store
            .admit_guest_operation_with_sinks(1000, &operation, &fence, &command, 0, Some(1), 1100,)
            .unwrap(),
        GuestAdmission::Pending(_)
    ));
    let pending = store.inspect_operation(1000, &operation, 1).unwrap();
    assert_eq!(pending.state, OperationReceiptState::Pending);
    assert_eq!(pending.operation, operation);
    assert_eq!(pending.operation_sequence, 1);
    assert_eq!(pending.accepted_sequence, 1);
    assert_eq!(
        pending.request_digest.as_deref(),
        Some(expected_digest.as_str())
    );
    assert_eq!(
        pending.response.as_deref(),
        Some(&Response::GuestPending {
            operation: operation.clone(),
        })
    );

    // Trusted runtime completion metadata fixture, not evidence of guest execution.
    let response = Response::Guest(GuestReply::ExecExit {
        exec: "exec-1".parse().unwrap(),
        exit_code: Some(0),
        signal: None,
        timed_out: false,
    });
    store
        .complete_guest_operation(
            1000,
            &operation,
            digest(&fence, &command).unwrap(),
            &response,
        )
        .unwrap();
    let complete = store.inspect_operation(1000, &operation, 1).unwrap();
    assert_eq!(complete.state, OperationReceiptState::Complete);
    assert_eq!(
        complete.request_digest.as_deref(),
        Some(expected_digest.as_str())
    );
    assert_eq!(complete.response.as_deref(), Some(&response));
}

#[test]
fn secret_injection_marker_precedes_delivery_and_survives_sqlite_reopen() {
    use sandboxd_protocol::exec::{ExecutionSpec, OutputPolicy, SecretValue, StdinMode};
    let (directory, mut store, fence, _) = active_store();
    let spec = ExecutionSpec {
        id: "private-exec".parse().unwrap(),
        argv: vec!["/bin/true".into()],
        use_image_defaults: false,
        cwd: "/".into(),
        uid: 0,
        gid: 0,
        supplementary_groups: Vec::new(),
        readonly_root: false,
        mounts: Vec::new(),
        max_processes: 64,
        environment: Default::default(),
        secret_environment: [(
            "TOKEN".into(),
            SecretValue("private-never-persisted".into()),
        )]
        .into(),
        pty: None,
        stdin: StdinMode::Closed,
        timeout_ms: 1000,
        detached: true,
        output_policy: OutputPolicy::Disabled,
        output_bytes: 0,
    };
    let command = GuestCommand::ExecStart {
        spec: Box::new(spec),
    };
    let operation = OperationId::new("inject-secret").unwrap();
    let GuestAdmission::Pending(key) = store
        .admit_guest_operation(1000, &operation, &fence, &command, 1100)
        .unwrap()
    else {
        panic!("pending intent required")
    };
    assert!(
        store
            .session_intent(1000, &key)
            .unwrap()
            .has_received_secrets
    );
    let saved: Vec<u8> = store
        .connection
        .query_row(
            "SELECT record FROM sessions WHERE sandbox=?1",
            [key.sandbox.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        !saved
            .windows(b"private-never-persisted".len())
            .any(|b| b == b"private-never-persisted")
    );
    store
        .complete_guest_operation(
            1000,
            &operation,
            digest(&fence, &command).unwrap(),
            &Response::Error(ApiError::new(
                ErrorCode::GuestHandshakeFailed,
                "delivery failed",
            )),
        )
        .unwrap();
    assert!(
        store
            .session_intent(1000, &key)
            .unwrap()
            .has_received_secrets
    );
    drop(store);
    // This metadata fixture has no VMM. Check the committed SQLite record,
    // without pretending it is sufficient for native process re-adoption.
    let connection = rusqlite::Connection::open(directory.path().join("state.sqlite3")).unwrap();
    let saved: Vec<u8> = connection
        .query_row(
            "SELECT record FROM sessions WHERE sandbox=?1",
            [key.sandbox.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    let reopened: crate::state::LaunchIntent = codec::decode_body(&saved).unwrap();
    assert!(reopened.has_received_secrets);
    // Sessions written before the marker existed cannot prove absence.
    let mut historical = serde_json::to_value(reopened).unwrap();
    historical
        .as_object_mut()
        .unwrap()
        .remove("has_received_secrets");
    let old: crate::state::LaunchIntent = serde_json::from_value(historical).unwrap();
    assert!(old.has_received_secrets);
}

#[test]
fn admission_rejects_stale_generation_owner_lease_and_paused_session() {
    let (_directory, mut store, fence, command) = active_store();
    let mut stale = fence.clone();
    stale.generation = SandboxGeneration::new(2).unwrap();
    assert!(
        store
            .admit_guest_operation(
                1000,
                &OperationId::new("stale-sandbox").unwrap(),
                &stale,
                &command,
                1100
            )
            .is_err()
    );
    let mut stale_session = fence.clone();
    stale_session.session_generation = Some(SessionGeneration::new(2).unwrap());
    assert!(
        store
            .admit_guest_operation(
                1000,
                &OperationId::new("stale-session").unwrap(),
                &stale_session,
                &command,
                1100
            )
            .is_err()
    );
    assert!(
        store
            .admit_guest_operation(
                2000,
                &OperationId::new("wrong-owner").unwrap(),
                &fence,
                &command,
                1100
            )
            .is_err()
    );
    assert!(
        store
            .admit_guest_operation(
                1000,
                &OperationId::new("expired").unwrap(),
                &fence,
                &command,
                4_000_000
            )
            .is_err()
    );
    let mut record = store.inspect(1000, &fence.sandbox).unwrap();
    let session = record.session.clone().unwrap();
    let key = SessionKey {
        sandbox: fence.sandbox.clone(),
        sandbox_generation: fence.generation,
        session: session.id,
        generation: fence.session_generation.unwrap(),
    };
    let mut intent = store.session_intent(1000, &key).unwrap();
    intent.state = SessionState::Paused;
    record.state = SandboxState::Paused;
    record.session.as_mut().unwrap().state = SessionState::Paused;
    let tx = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    tx.execute(
        "UPDATE sessions SET record=?1 WHERE session_id=?2",
        params![codec::encode_body(&intent).unwrap(), key.session.as_str()],
    )
    .unwrap();
    tx.execute(
        "UPDATE sandboxes SET record=?1 WHERE id=?2",
        params![codec::encode_body(&record).unwrap(), record.id.as_str()],
    )
    .unwrap();
    tx.commit().unwrap();
    assert!(
        store
            .admit_guest_operation(
                1000,
                &OperationId::new("paused").unwrap(),
                &fence,
                &command,
                1100
            )
            .is_err()
    );
}
