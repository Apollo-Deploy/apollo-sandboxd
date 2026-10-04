mod support;
use apollo_sandboxd::error::Error;
use sandboxd_protocol::*;
use support::*;

#[test]
fn lease_expiry_cannot_be_reversed_by_clock_rollback() {
    let dir = directory();
    let path = dir.path().canonicalize().expect("canonical path");
    let mut store = open(&path, 100);
    let record = sandbox(
        store
            .mutate(1000, &op("create"), &create("clock", None), 1000)
            .expect("create"),
    );
    assert_eq!(store.expire_leases(11_000).expect("expiry"), 1);
    drop(store);
    let mut store = open(&path, 100);
    let result = store.mutate(
        1000,
        &op("renew-after-rollback"),
        &Mutation::Renew {
            fence: fence(&record),
            sequence: 1,
            duration_seconds: 20,
        },
        5000,
    );
    assert!(matches!(
        result,
        Err(Error::Api(ApiError {
            code: ErrorCode::LeaseExpired,
            ..
        }))
    ));
}

#[test]
fn replay_is_durable_and_destroyed_identity_cannot_roll_back_generation() {
    let dir = directory();
    let path = dir.path().canonicalize().expect("canonical path");
    let mut store = open(&path, 100);
    let response = store
        .mutate(1000, &op("create"), &create("stable", None), 1000)
        .expect("create");
    let first = sandbox(response.clone());
    drop(store);
    let mut store = open(&path, 100);
    assert_eq!(
        store
            .mutate(1000, &op("create"), &create("stable", None), 2000)
            .expect("replay"),
        response
    );
    let conflict = store.mutate(1000, &op("create"), &create("another", None), 2000);
    assert!(matches!(
        conflict,
        Err(Error::Api(ApiError {
            code: ErrorCode::OperationConflict,
            ..
        }))
    ));
    assert!(store.inspect(2000, &first.id).is_err());
    let destroy = Mutation::Destroy {
        fence: fence(&first),
    };
    let result = store
        .mutate(1000, &op("destroy"), &destroy, 2000)
        .expect("destroy");
    assert_eq!(
        store
            .mutate(1000, &op("destroy"), &destroy, 3000)
            .expect("replay destroy"),
        result
    );
    assert!(
        store
            .mutate(1000, &op("rollback"), &create("stable", None), 3000)
            .is_err()
    );
    let second = sandbox(
        store
            .mutate(
                1000,
                &op("recreate"),
                &create("stable", Some(first.generation)),
                3000,
            )
            .expect("recreate"),
    );
    assert_eq!(second.generation.get(), 2);
    let stale = store.mutate(1000, &op("stale-destroy"), &destroy, 4000);
    assert!(matches!(
        stale,
        Err(Error::Api(ApiError {
            code: ErrorCode::StaleGeneration,
            ..
        }))
    ));
    assert_eq!(
        store
            .inspect(1000, &second.id)
            .expect("inspect")
            .generation
            .get(),
        2
    );
    assert_eq!(store.events(1000, 1, 100).expect("events").events.len(), 3);
}

#[test]
fn expiry_scan_reaches_expired_records_beyond_a_full_batch_of_live_records() {
    let dir = directory();
    let path = dir.path().canonicalize().expect("canonical path");
    let mut store = open(&path, 1000);
    for index in 0..260 {
        let id = format!("live-{index}");
        store
            .mutate(1000, &op(&id), &create(&id, None), 20_000)
            .expect("live create");
    }
    store
        .mutate(1000, &op("expired"), &create("expired", None), 1000)
        .expect("create expired");
    assert_eq!(store.expire_leases(15_000).expect("expiry"), 1);
    assert_eq!(store.expire_leases(15_000).expect("repeat expiry"), 0);
    assert_eq!(
        store.events(1000, 262, 100).expect("expiry event").events[0].kind,
        EventKind::LeaseExpired
    );
}
