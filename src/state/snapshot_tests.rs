use super::{
    allocation::{self, Pool},
    checkpoint_tests::fixture,
    snapshot::*,
};
use crate::snapshot::SnapshotSettings;
use rusqlite::params;
use sandboxd_protocol::*;

fn limits() -> SnapshotSettings {
    SnapshotSettings {
        directory: "/snapshots".into(),
        key_file: "/key".into(),
        max_snapshots_per_sandbox: 2,
        max_total_bytes: 1 << 40,
        max_concurrent_operations: 2,
        max_restore_memory_bytes: 1 << 40,
    }
}
fn create(fence: Fence) -> SnapshotCommand {
    SnapshotCommand::Create {
        id: "full".parse().unwrap(),
        fence,
        secret_policy: SnapshotSecretPolicy::Reject,
    }
}
#[test]
fn full_snapshot_admission_is_fenced_idempotent_and_reserves_cid_after_compute_exit() {
    let (directory, mut store, fence) = fixture();
    let command = create(fence.clone());
    let op = OperationId::with_sequence(1, "full").unwrap();
    assert_eq!(
        store
            .admit_snapshot(1001, &op, 1, &command, &limits(), 1002)
            .err()
            .unwrap()
            .api()
            .code,
        ErrorCode::SandboxNotFound
    );
    assert_eq!(
        store
            .admit_snapshot(1000, &op, 1, &command, &limits(), u64::MAX)
            .err()
            .unwrap()
            .api()
            .code,
        ErrorCode::LeaseExpired
    );
    let SnapshotAdmission::Pending(intent) = store
        .admit_snapshot(1000, &op, 1, &command, &limits(), 1002)
        .unwrap()
    else {
        panic!("pending");
    };
    assert!(!intent.capture_started);
    store
        .snapshot_update(1000, &op, |intent| {
            intent.capture_started = true;
            Ok(())
        })
        .unwrap();
    assert!(store.snapshot_intent(1000, &op).unwrap().capture_started);
    assert!(matches!(
        store
            .admit_snapshot(1000, &op, 1, &command, &limits(), u64::MAX)
            .unwrap(),
        SnapshotAdmission::Pending(_)
    ));
    let other = SnapshotCommand::Delete {
        id: "full".parse().unwrap(),
        fence: fence.clone(),
    };
    assert_eq!(
        store
            .admit_snapshot(1000, &op, 1, &other, &limits(), 1002)
            .err()
            .unwrap()
            .api()
            .code,
        ErrorCode::OperationConflict
    );
    assert_eq!(
        store
            .mutate(
                1000,
                &OperationId::new("blocked").unwrap(),
                &Mutation::Renew {
                    fence,
                    sequence: 1,
                    duration_seconds: 3600
                },
                1003
            )
            .err()
            .unwrap()
            .api()
            .code,
        ErrorCode::SessionUnavailable
    );
    store
        .connection
        .execute(
            "DELETE FROM sessions WHERE session_id=?1",
            [intent.record.source.key.session.as_str()],
        )
        .unwrap();
    let tx = store.connection.transaction().unwrap();
    assert_eq!(
        allocation::first_free(
            &tx,
            Pool::Cid,
            intent.record.source.cid,
            intent.record.source.cid + 10
        )
        .unwrap(),
        intent.record.source.cid + 1
    );
    tx.rollback().unwrap();
    let path = directory.path().join("state.sqlite3");
    drop(store);
    let db = rusqlite::Connection::open(path).unwrap();
    let count: u32 = db
        .query_row("SELECT COUNT(*) FROM snapshot_intents", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
    let cid: u32 = db
        .query_row("SELECT cid FROM snapshots", [], |r| r.get(0))
        .unwrap();
    assert_eq!(cid, intent.record.source.cid);
}
#[test]
fn full_snapshot_secret_policy_is_monotonic_and_opt_in_is_explicit() {
    let (_directory, mut store, fence) = fixture();
    let session = store
        .inspect(1000, &fence.sandbox)
        .unwrap()
        .session
        .unwrap();
    let key = super::SessionKey {
        sandbox: fence.sandbox.clone(),
        sandbox_generation: fence.generation,
        session: session.id,
        generation: session.generation,
    };
    let mut launch = store.session_intent(1000, &key).unwrap();
    launch.has_received_secrets = true;
    store
        .connection
        .execute(
            "UPDATE sessions SET record=?1 WHERE session_id=?2",
            params![codec::encode_body(&launch).unwrap(), key.session.as_str()],
        )
        .unwrap();
    let op = OperationId::with_sequence(1, "secret").unwrap();
    assert_eq!(
        store
            .admit_snapshot(1000, &op, 1, &create(fence.clone()), &limits(), 1002)
            .err()
            .unwrap()
            .api()
            .code,
        ErrorCode::SecretSnapshotForbidden
    );
    let command = SnapshotCommand::Suspend {
        id: "full".parse().unwrap(),
        fence,
        secret_policy: SnapshotSecretPolicy::AllowEncrypted,
    };
    let SnapshotAdmission::Pending(intent) = store
        .admit_snapshot(1000, &op, 1, &command, &limits(), 1002)
        .unwrap()
    else {
        panic!("pending");
    };
    assert!(intent.record.source.has_received_secrets);
}
#[test]
fn full_snapshot_ram_rejection_rolls_back_disk_and_cid_reservations() {
    let (_directory, mut store, fence) = fixture();
    let mut policy = limits();
    policy.max_restore_memory_bytes = 1;
    let op = OperationId::with_sequence(1, "bounded").unwrap();
    assert_eq!(
        store
            .admit_snapshot(1000, &op, 1, &create(fence.clone()), &policy, 1002)
            .err()
            .unwrap()
            .api()
            .code,
        ErrorCode::QuotaExceeded
    );
    for table in ["snapshots", "snapshot_intents", "checkpoints"] {
        let count: u32 = store
            .connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }
    assert!(matches!(
        store
            .admit_snapshot(1000, &op, 1, &create(fence), &limits(), 1002)
            .unwrap(),
        SnapshotAdmission::Pending(_)
    ));
}

#[test]
fn full_snapshot_restore_allocates_fresh_identity_and_can_abort_before_effects() {
    let (_directory, mut store, fence) = fixture();
    let op = OperationId::with_sequence(1, "restore").unwrap();
    let SnapshotAdmission::Pending(captured) = store
        .admit_snapshot(1000, &op, 1, &create(fence.clone()), &limits(), 1002)
        .unwrap()
    else {
        panic!("pending");
    };
    let source = captured.record.source;
    // Persist a stopped source and admitted restore, then exercise the real allocation transaction.
    let mut sandbox = store.inspect(1000, &fence.sandbox).unwrap();
    store
        .connection
        .execute(
            "DELETE FROM sessions WHERE session_id=?1",
            [source.key.session.as_str()],
        )
        .unwrap();
    sandbox.session = None;
    sandbox.lease.session_generation = None;
    sandbox.state = SandboxState::Suspended;
    let tx = store.connection.transaction().unwrap();
    super::lease::save(&tx, &sandbox).unwrap();
    tx.commit().unwrap();
    store
        .snapshot_update(1000, &op, |intent| {
            intent.command = SnapshotCommand::Restore {
                id: "full".parse().unwrap(),
                fence: Fence {
                    session_generation: None,
                    ..fence.clone()
                },
            };
            Ok(())
        })
        .unwrap();
    let pools = crate::config::IdentityPools {
        uid_first: 200000,
        uid_last: 200001,
        gid_first: 300000,
        gid_last: 300001,
        cid_first: 3,
        cid_last: 4,
    };
    let context = || super::SessionPreparation {
        pins: &source.pins,
        pools: &pools,
        host_boot_id: "00000000-0000-4000-8000-000000000002",
        now_ms: 1003,
    };
    let restored = store
        .prepare_snapshot_session(1000, &op, context())
        .unwrap();
    assert_eq!(restored.cid, source.cid);
    assert_ne!(restored.key.session, source.key.session);
    assert!(restored.key.generation > source.key.generation);
    assert_ne!(restored.boot_nonce, source.boot_nonce);
    assert_eq!(restored.has_received_secrets, source.has_received_secrets);
    assert_eq!(
        store
            .prepare_snapshot_session(1000, &op, context())
            .unwrap()
            .key,
        restored.key
    );
    assert!(store.abort_snapshot_before_launch(1000, &op, 1004).unwrap());
    assert!(store.abort_snapshot_before_launch(1000, &op, 1005).unwrap());
    assert!(
        store
            .snapshot_intent(1000, &op)
            .unwrap()
            .restore_aborted_before_launch
    );
    assert!(
        store
            .inspect(1000, &fence.sandbox)
            .unwrap()
            .session
            .is_none()
    );
    let tx = store.connection.transaction().unwrap();
    assert_eq!(
        allocation::first_free(&tx, Pool::Cid, source.cid, source.cid + 1).unwrap(),
        source.cid + 1
    );
}
#[test]
fn full_snapshot_queries_hide_unpublished_and_foreign_records() {
    let (_directory, mut store, fence) = fixture();
    let op = OperationId::with_sequence(1, "query").unwrap();
    store
        .admit_snapshot(1000, &op, 1, &create(fence.clone()), &limits(), 1002)
        .unwrap();
    let id = SnapshotId::new("full").unwrap();
    assert_eq!(
        store.inspect_snapshot(1000, &id).unwrap_err().api().code,
        ErrorCode::SnapshotNotFound
    );
    assert_eq!(
        store.inspect_snapshot(1001, &id).unwrap_err().api().code,
        ErrorCode::SnapshotNotFound
    );
    assert!(
        store
            .list_snapshots(1000, &fence.sandbox, None, 1)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .list_snapshots(1001, &fence.sandbox, None, 1)
            .unwrap_err()
            .api()
            .code,
        ErrorCode::SandboxNotFound
    );
    assert_eq!(
        store
            .list_snapshots(1000, &fence.sandbox, None, 0)
            .unwrap_err()
            .api()
            .code,
        ErrorCode::InvalidRequest
    );
}
