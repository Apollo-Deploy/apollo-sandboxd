//! Independent red-team attacks against present metadata paths.
//! These tests intentionally document release-gating behavior; they do not
//! claim that the absent VM path has been exercised.
use apollo_sandboxd::{
    config::{LeaseConfig, Quotas},
    state::Store,
};
use rusqlite::Connection;
use sandboxd_protocol::*;
use std::{collections::BTreeMap, os::unix::fs::PermissionsExt};

fn open(dir: &std::path::Path, receipts: u32) -> Store {
    Store::open(
        dir,
        Quotas {
            max_active_sandboxes: 16,
            max_booting_sandboxes: 4,
            max_sandbox_identities: 8,
            max_operation_receipts: receipts,
            max_vcpus: 2,
            max_memory_mib: 256,
            max_state_disk_mib: 256,
        },
        LeaseConfig { max_seconds: 60 },
        16,
    )
    .expect("store")
}

fn open_result(dir: &std::path::Path, receipts: u32) -> apollo_sandboxd::error::Result<Store> {
    Store::open(
        dir,
        Quotas {
            max_active_sandboxes: 16,
            max_booting_sandboxes: 4,
            max_sandbox_identities: 8,
            max_operation_receipts: receipts,
            max_vcpus: 2,
            max_memory_mib: 256,
            max_state_disk_mib: 256,
        },
        LeaseConfig { max_seconds: 60 },
        16,
    )
}

fn sandbox_spec() -> SandboxSpec {
    SandboxSpec {
        architecture: Architecture::X86_64,
        image: ImageDigest::new(format!("sha256:{}", "a".repeat(64))).expect("digest"),
        kernel_profile: "kernel".into(),
        runtime_profile: "runtime".into(),
        persistence: Persistence::Ephemeral,
        resources: Resources {
            vcpus: 1,
            memory_mib: 128,
            state_disk_mib: 128,
            host_memory_max_bytes: 128 * 1024 * 1024,
            cpu_quota_us: 100_000,
            cpu_period_us: 100_000,
            cpu_profile: None,
            cpuset: None,
            state_rate_limiter: None,
        },
        network: NetworkMode::None,
        volumes: Vec::new(),
        environment: BTreeMap::new(),
        lifetimes: Lifetimes {
            sandbox_ttl_seconds: 30,
            session_max_seconds: 30,
            idle_seconds: 10,
        },
    }
}

fn create(id: &str) -> Mutation {
    Mutation::Create {
        sandbox: SandboxId::new(id).expect("id"),
        expected_generation: None,
        spec: Box::new(sandbox_spec()),
        lease_seconds: 10,
    }
}

fn record(response: Response) -> Sandbox {
    match response {
        Response::Sandbox(value) => *value,
        _ => std::process::abort(),
    }
}

fn fence(value: &Sandbox) -> Fence {
    Fence {
        sandbox: value.id.clone(),
        generation: value.generation,
        session_generation: None,
        lease: value.lease.id.clone(),
    }
}

#[test]
fn terminal_receipts_are_collected_before_capacity_blocks_lifecycle() {
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("directory");
    let path = dir.path().canonicalize().expect("path");
    let mut store = open(&path, 1);
    let value = record(
        store
            .mutate(
                1000,
                &OperationId::new("create").expect("op"),
                &create("quota"),
                1000,
            )
            .expect("create"),
    );
    let result = store.mutate(
        1000,
        &OperationId::new("destroy").expect("op"),
        &Mutation::Destroy {
            fence: fence(&value),
        },
        1000,
    );
    assert!(
        result.is_ok(),
        "terminal history must not exhaust lifecycle capacity"
    );
}

#[test]
fn sandbox_identity_churn_reclaims_only_terminal_tombstones() {
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("directory");
    let path = dir.path().canonicalize().expect("path");
    let mut store = open(&path, 8);
    let mut old = None;
    for index in 0..20_000_u32 {
        let id = format!("churn-{index}");
        let created = record(
            store
                .mutate(
                    1000,
                    &OperationId::new(format!("c-{index}")).expect("op"),
                    &create(&id),
                    index as u64,
                )
                .expect("create during churn"),
        );
        if index == 0 {
            old = Some(created.clone());
        }
        store
            .mutate(
                1000,
                &OperationId::new(format!("d-{index}")).expect("op"),
                &Mutation::Destroy {
                    fence: fence(&created),
                },
                index as u64 + 1,
            )
            .expect("destroy during churn");
    }
    let old = old.expect("old identity");
    let recreated = record(
        store
            .mutate(
                1000,
                &OperationId::new("recreate").expect("op"),
                &create("churn-0"),
                40_001,
            )
            .expect("recreate after tombstone collection"),
    );
    assert!(recreated.generation > old.generation);
    let stale = store.mutate(
        1000,
        &OperationId::new("stale-old-fence").expect("op"),
        &Mutation::Destroy { fence: fence(&old) },
        40_002,
    );
    assert!(matches!(stale, Err(apollo_sandboxd::error::Error::Api(_))));
}

#[test]
fn operation_watermark_replays_and_rejects_old_unseen_sequences() {
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("directory");
    let path = dir.path().canonicalize().expect("path");
    let mut store = open(&path, 2);
    let create = create("watermark");
    let first = store
        .mutate_checked_sequenced(
            1000,
            &OperationId::with_sequence(1, "first").unwrap(),
            &create,
            1000,
            Some(1),
            || Ok(()),
        )
        .expect("first operation");
    let replay = store
        .mutate_checked_sequenced(
            1000,
            &OperationId::with_sequence(1, "first").unwrap(),
            &create,
            1001,
            Some(1),
            || panic!("replay must not run admission"),
        )
        .expect("replay");
    assert_eq!(first, replay);
    let out_of_order = store.mutate_checked_sequenced(
        1000,
        &OperationId::with_sequence(1, "old-unseen").unwrap(),
        &Mutation::AcquireLease {
            fence: fence(&record(first.clone())),
            duration_seconds: 10,
        },
        1002,
        Some(1),
        || Ok(()),
    );
    assert!(matches!(
        out_of_order,
        Err(apollo_sandboxd::error::Error::Api(ApiError {
            code: ErrorCode::OperationReceiptUnavailable,
            ..
        }))
    ));
    assert_eq!(store.operation_watermark(1000).unwrap(), 1);
    let skipped = store.mutate_checked_sequenced(
        1000,
        &OperationId::with_sequence(3, "skipped").unwrap(),
        &Mutation::AcquireLease {
            fence: fence(&record(first)),
            duration_seconds: 10,
        },
        1003,
        Some(3),
        || Ok(()),
    );
    assert!(matches!(
        skipped,
        Err(apollo_sandboxd::error::Error::Api(ApiError {
            code: ErrorCode::OperationOutOfOrder,
            ..
        }))
    ));
}

#[test]
fn duplicated_sandbox_identity_and_expiry_fields_fail_closed_on_open() {
    for (column, replacement) in [
        ("generation", "99"),
        ("id", "'different-id'"),
        ("lease_expires_at", "999999999"),
    ] {
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("directory");
        let path = dir.path().canonicalize().expect("path");
        let mut store = open(&path, 16);
        let value = record(
            store
                .mutate(
                    1000,
                    &OperationId::new("create").expect("op"),
                    &create("corrupt"),
                    1000,
                )
                .expect("create"),
        );
        drop(store);
        let connection = Connection::open(path.join("state.sqlite3")).expect("database");
        connection
            .execute_batch(&format!(
                "UPDATE sandboxes SET {column}={replacement} WHERE id='{}'",
                value.id.as_str()
            ))
            .expect("corrupt duplicated index");
        drop(connection);
        assert!(
            open_result(&path, 16).is_err(),
            "corruption in {column} was accepted"
        );
    }
}
