//! Real durable-store contracts. These tests create no VM and do not qualify boot.
mod support;
use apollo_sandboxd::{
    config::{IdentityPools, LeaseConfig},
    state::{SessionControlContext, SessionPins, SessionPreparation, Store},
};
use sandboxd_protocol::*;
use support::*;

const BOOT: &str = "00000000-0000-4000-8000-000000000001";
fn pools() -> IdentityPools {
    IdentityPools {
        uid_first: 200000,
        uid_last: 200001,
        gid_first: 300000,
        gid_last: 300001,
        cid_first: 3,
        cid_last: 4,
    }
}
fn pins(record: &Sandbox) -> SessionPins {
    SessionPins {
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
    }
}
fn reserve(
    store: &mut Store,
    record: &Sandbox,
    operation: &str,
) -> apollo_sandboxd::error::Result<apollo_sandboxd::state::PreparedSession> {
    store.prepare_session(
        1000,
        &op(operation),
        &fence(record),
        SessionPreparation {
            pins: &pins(record),
            pools: &pools(),
            host_boot_id: BOOT,
            now_ms: 2000,
        },
    )
}

#[test]
fn reservation_replay_restart_and_exhaustion_never_duplicate_allocations() {
    let directory = directory();
    let path = directory.path().canonicalize().expect("path");
    let mut store = open(&path, 20);
    let a = sandbox(
        store
            .mutate(1000, &op("create-a"), &create("a", None), 1000)
            .expect("create"),
    );
    let b = sandbox(
        store
            .mutate(1000, &op("create-b"), &create("b", None), 1000)
            .expect("create"),
    );
    let c = sandbox(
        store
            .mutate(1000, &op("create-c"), &create("c", None), 1000)
            .expect("create"),
    );
    let first = reserve(&mut store, &a, "start-a").expect("reserve");
    let second = reserve(&mut store, &b, "start-b").expect("reserve");
    let one = first.intent.expect("intent");
    let two = second.intent.expect("intent");
    assert_ne!(one.uid, two.uid);
    assert_ne!(one.gid, two.gid);
    assert_ne!(one.cid, two.cid);
    assert_ne!(one.key.session, two.key.session);
    assert_ne!(one.boot_nonce, two.boot_nonce);
    assert!(reserve(&mut store, &c, "start-c").is_err());
    assert_eq!(
        store.inspect(1000, &c.id).expect("unchanged").state,
        SandboxState::Stopped
    );
    drop(store);
    let mut store = open(&path, 20);
    // A committed retry remains valid after catalog/pool settings change.
    let mut wrong_pins = pins(&a);
    wrong_pins.runtime_profile = "removed".into();
    let replay = store
        .prepare_session(
            1000,
            &op("start-a"),
            &fence(&a),
            SessionPreparation {
                pins: &wrong_pins,
                pools: &pools(),
                host_boot_id: "invalid",
                now_ms: 0,
            },
        )
        .expect("receipt before policy");
    assert!(replay.replayed);
    assert_eq!(replay.response, first.response);
    assert_eq!(replay.intent.expect("same active intent").key, one.key);
    assert_eq!(store.session_intents(None, 10).expect("recovery").len(), 2);
    store
        .abort_session_preparation(1000, &one.key, 2100)
        .expect("never launched");
    let third = reserve(&mut store, &c, "start-c")
        .expect("slot reclaimed")
        .intent
        .expect("intent");
    assert_eq!(
        (third.uid, third.gid, third.cid),
        (one.uid, one.gid, one.cid)
    );
}

#[test]
fn old_receipt_and_session_fences_cannot_authorize_a_new_incarnation() {
    let directory = directory();
    let path = directory.path().canonicalize().expect("path");
    let mut store = open(&path, 20);
    let initial = sandbox(
        store
            .mutate(1000, &op("create"), &create("a", None), 1000)
            .expect("create"),
    );
    let old = reserve(&mut store, &initial, "start-1")
        .expect("first")
        .intent
        .expect("intent");
    store
        .abort_session_preparation(1000, &old.key, 2100)
        .expect("abort");
    let stopped = store.inspect(1000, &initial.id).expect("stopped");
    let current = reserve(&mut store, &stopped, "start-2")
        .expect("second")
        .intent
        .expect("intent");
    assert!(current.key.generation > old.key.generation);
    assert!(store.begin_session_launch(1000, &old.key, 2200).is_err());
    assert!(
        store
            .abort_session_preparation(1000, &old.key, 2200)
            .is_err()
    );
    assert!(
        reserve(&mut store, &initial, "start-1")
            .expect("old receipt")
            .intent
            .is_none()
    );
    assert!(
        reserve(&mut store, &initial, "create").is_err(),
        "operation namespaces must not collide"
    );
    store
        .begin_session_launch(1000, &current.key, 2200)
        .expect("durable launch boundary");
    assert!(
        store
            .begin_session_launch(1000, &current.key, 2201)
            .is_err(),
        "no second launch"
    );
    assert!(
        store
            .abort_session_preparation(1000, &current.key, 2201)
            .is_err(),
        "uncertain VMM keeps allocation"
    );
    drop(store);
    let store = open(&path, 20);
    assert_eq!(
        store
            .session_intent(1000, &current.key)
            .expect("durable intent")
            .state,
        SessionState::JailerStarting
    );
}

#[test]
fn lease_expiry_and_owner_checks_prevent_runtime_effect_authorization() {
    let directory = directory();
    let path = directory.path().canonicalize().expect("path");
    let mut store = open(&path, 20);
    let initial = sandbox(
        store
            .mutate(1000, &op("create"), &create("a", None), 1000)
            .expect("create"),
    );
    let prepared = reserve(&mut store, &initial, "start").expect("reserve");
    let intent = prepared.intent.expect("intent");
    let active = sandbox(prepared.response);
    assert!(store.session_intent(2000, &intent.key).is_err());
    assert!(
        store
            .abort_session_preparation(2000, &intent.key, 2100)
            .is_err()
    );
    assert!(
        store
            .mutate(
                1000,
                &op("destroy"),
                &Mutation::Destroy {
                    fence: fence(&active)
                },
                2100
            )
            .is_err()
    );
    assert!(
        store
            .begin_session_launch(1000, &intent.key, 11000)
            .is_err()
    );
    assert_eq!(
        store
            .session_intent(1000, &intent.key)
            .expect("retained")
            .state,
        SessionState::Preparing
    );
    store
        .abort_session_preparation(1000, &intent.key, 12000)
        .expect("safe without active lease because never launched");
}

#[test]
fn booting_quota_rejection_does_not_spend_generation_or_identity() {
    let directory = directory();
    let path = directory.path().canonicalize().expect("path");
    let mut limits = quotas();
    limits.max_booting_sandboxes = 1;
    let mut store =
        Store::open(&path, limits, LeaseConfig { max_seconds: 3600 }, 20).expect("store");
    let a = sandbox(
        store
            .mutate(1000, &op("a"), &create("a", None), 1000)
            .expect("create"),
    );
    let b = sandbox(
        store
            .mutate(1000, &op("b"), &create("b", None), 1000)
            .expect("create"),
    );
    let first = reserve(&mut store, &a, "start-a")
        .expect("reserve")
        .intent
        .expect("intent");
    assert!(reserve(&mut store, &b, "start-b").is_err());
    store
        .abort_session_preparation(1000, &first.key, 2100)
        .expect("abort");
    let second = reserve(&mut store, &b, "start-b")
        .expect("retry")
        .intent
        .expect("intent");
    assert_eq!(second.key.generation.get(), 1);
}

#[test]
fn corrupted_session_index_is_rejected_on_restart() {
    let directory = directory();
    let path = directory.path().canonicalize().expect("path");
    let mut store = open(&path, 20);
    let a = sandbox(
        store
            .mutate(1000, &op("a"), &create("a", None), 1000)
            .expect("create"),
    );
    reserve(&mut store, &a, "start-a").expect("reserve");
    drop(store);
    let connection = rusqlite::Connection::open(path.join("state.sqlite3")).expect("database");
    connection
        .execute("UPDATE sessions SET cid=100 WHERE sandbox='a'", [])
        .expect("corrupt index");
    drop(connection);
    assert!(Store::open(&path, quotas(), LeaseConfig { max_seconds: 3600 }, 20).is_err());
}

#[test]
fn public_start_replay_is_canonical_and_survives_reopen() {
    let directory = directory();
    let path = directory.path().canonicalize().expect("path");
    let mut store = open(&path, 20);
    let initial = sandbox(
        store
            .mutate(1000, &op("create-public"), &create("public", None), 1000)
            .expect("create"),
    );
    let first = store
        .begin_session_control(
            1000,
            &op("public-start"),
            &fence(&initial),
            SessionControl::Start,
            SessionControlContext {
                pins: Some(&pins(&initial)),
                pools: &pools(),
                host_boot_id: BOOT,
                now_ms: 2000,
            },
        )
        .expect("admit start");
    assert!(!first.replayed);
    let first_key = first.key.clone().expect("owned incarnation");
    drop(store);
    let mut store = open(&path, 20);
    let replay = store
        .begin_session_control(
            1000,
            &op("public-start"),
            &fence(&initial),
            SessionControl::Start,
            SessionControlContext {
                pins: None,
                pools: &pools(),
                host_boot_id: "invalid",
                now_ms: 2500,
            },
        )
        .expect("replay");
    assert!(replay.replayed);
    assert_eq!(replay.key.expect("same current incarnation"), first_key);
    assert_eq!(replay.response, first.response);

    let collision = store.begin_session_control(
        1000,
        &op("create-public"),
        &fence(&initial),
        SessionControl::Start,
        SessionControlContext {
            pins: Some(&pins(&initial)),
            pools: &pools(),
            host_boot_id: BOOT,
            now_ms: 2500,
        },
    );
    assert!(
        matches!(collision, Err(apollo_sandboxd::error::Error::Api(api)) if api.code == ErrorCode::OperationConflict)
    );
}

#[test]
fn public_start_rejects_stale_lease_before_allocating() {
    let directory = directory();
    let path = directory.path().canonicalize().expect("path");
    let mut store = open(&path, 20);
    let initial = sandbox(
        store
            .mutate(1000, &op("create-expired"), &create("expired", None), 1000)
            .expect("create"),
    );
    let result = store.begin_session_control(
        1000,
        &op("expired-start"),
        &fence(&initial),
        SessionControl::Start,
        SessionControlContext {
            pins: Some(&pins(&initial)),
            pools: &pools(),
            host_boot_id: BOOT,
            now_ms: 12000,
        },
    );
    assert!(
        matches!(result, Err(apollo_sandboxd::error::Error::Api(api)) if api.code == ErrorCode::LeaseExpired)
    );
    assert_eq!(
        store.inspect(1000, &initial.id).expect("record").state,
        SandboxState::Stopped
    );
}

#[test]
fn incomplete_cleanup_does_not_stop_or_release_session_identity() {
    let directory = directory();
    let path = directory.path().canonicalize().expect("path");
    let mut store = open(&path, 20);
    let initial = sandbox(
        store
            .mutate(1000, &op("create-stop"), &create("stop", None), 1000)
            .expect("create"),
    );
    let prepared = reserve(&mut store, &initial, "start-stop").expect("reserve");
    let old = prepared.intent.expect("intent");
    let mut terminating = old.clone();
    terminating.state = SessionState::Terminating;
    let connection = rusqlite::Connection::open(path.join("state.sqlite3")).expect("database");
    connection
        .execute(
            "UPDATE sessions SET record=?1 WHERE session_id=?2",
            rusqlite::params![
                codec::encode_body(&terminating).expect("encode"),
                old.key.session.as_str()
            ],
        )
        .expect("fixture terminating intent");
    drop(connection);
    let cleanup = store.record_session_stopped(
        1000,
        &old.key,
        apollo_sandboxd::state::CleanupProof::incomplete(old.key.clone()),
        3000,
    );
    assert!(
        cleanup.is_err(),
        "unobserved cleanup must not stop a session"
    );
    let current = store.inspect(1000, &initial.id).expect("current");
    assert_eq!(current.state, SandboxState::Starting);
    assert!(current.session.is_some());
}
