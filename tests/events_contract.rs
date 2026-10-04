mod support;
use sandboxd_protocol::*;
use support::*;

#[test]
fn event_sequences_and_gaps_are_private_to_the_authenticated_owner() {
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let mut store = open(&path, 2);
    store
        .mutate(1000, &op("a1"), &create("a1", None), 1000)
        .expect("a1");
    store
        .mutate(2000, &op("b1"), &create("b1", None), 1000)
        .expect("b1");
    store
        .mutate(1000, &op("a2"), &create("a2", None), 1000)
        .expect("a2");
    let page = store.events(1000, 1, 10).expect("events");
    assert_eq!(page.gap, Some((1, 2)));
    assert_eq!(page.events[0].sequence, 2);
    assert_eq!(page.next_sequence, 3);
    let page = store.events(2000, 1, 10).expect("events");
    assert_eq!(page.gap, None);
    assert_eq!(page.events[0].sequence, 1);
    assert_eq!(page.next_sequence, 2);
    store
        .mutate(1000, &op("a3"), &create("a3", None), 1000)
        .expect("a3");
    drop(store);
    let store = open(&path, 2);
    let evicted = store.events(2000, 1, 10).expect("evicted");
    assert_eq!(evicted.gap, Some((1, 2)));
    assert!(evicted.events.is_empty());
    assert_eq!(evicted.next_sequence, 2);
    let unknown = store.events(3000, 1, 10).expect("unknown owner");
    assert_eq!(unknown.gap, None);
    assert_eq!(unknown.next_sequence, 1);
    assert!(unknown.events.is_empty());
}

#[test]
fn stopped_identity_can_acquire_a_new_lease_without_reviving_the_old_token() {
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let mut store = open(&path, 20);
    let first = sandbox(
        store
            .mutate(1000, &op("create"), &create("leased", None), 1000)
            .expect("create"),
    );
    let acquire = Mutation::AcquireLease {
        fence: fence(&first),
        duration_seconds: 20,
    };
    assert!(store.mutate(2000, &op("steal"), &acquire, 12_000).is_err());
    assert!(
        store
            .mutate(1000, &op("too-early"), &acquire, 2000)
            .is_err()
    );
    store.expire_leases(11_000).expect("expiry");
    let result = store
        .mutate(1000, &op("acquire"), &acquire, 12_000)
        .expect("acquire");
    let second = sandbox(result.clone());
    assert_eq!(first.generation, second.generation);
    assert_ne!(first.lease.id, second.lease.id);
    assert_eq!(second.lease.renewal_sequence, 0);
    assert_eq!(
        store
            .mutate(1000, &op("acquire"), &acquire, 13_000)
            .expect("replay"),
        result
    );
    assert!(
        store
            .mutate(
                1000,
                &op("old-destroy"),
                &Mutation::Destroy {
                    fence: fence(&first)
                },
                13_000
            )
            .is_err()
    );
    store
        .mutate(
            1000,
            &op("destroy"),
            &Mutation::Destroy {
                fence: fence(&second),
            },
            13_000,
        )
        .expect("new lease permits cleanup");
    let events = store.events(1000, 1, 20).expect("events");
    assert_eq!(
        events
            .events
            .iter()
            .filter(|event| event.kind == EventKind::LeaseExpired)
            .count(),
        1
    );
}
