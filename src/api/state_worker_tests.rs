use super::*;
use crate::{api::handlers_tests, config::Config};
use sandboxd_protocol::*;
use std::{os::unix::fs::PermissionsExt, sync::Arc, time::Duration};
use tokio::time::Instant;

#[tokio::test]
async fn sqlite_busy_cannot_exceed_queue_bound_or_request_deadline() {
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("private directory");
    let path = dir.path().canonicalize().expect("path");
    let mut config: Config =
        toml::from_str(include_str!("../../config.example.toml")).expect("example schema");
    config.daemon.max_connections = 1;
    let store = Store::open(&path, config.quotas.clone(), config.leases.clone(), 16)
        .expect("real SQLite store");
    let blocker = rusqlite::Connection::open(path.join("state.sqlite3")).expect("writer");
    blocker
        .execute_batch("BEGIN IMMEDIATE")
        .expect("hold writer lock");
    let (client, worker) = start(store, Arc::new(config));
    client.expire().expect("submit expiry");
    // Wait until the worker dequeues expiry; the real transaction is now blocked.
    tokio::time::timeout(Duration::from_secs(1), async {
        while client.0.capacity() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("expiry started");
    let peer = Peer {
        uid: 1000,
        gid: 1000,
        pid: 1,
    };
    let deadline = Instant::now() + Duration::from_millis(100);
    let waiting = client.clone();
    let request = tokio::spawn(async move {
        waiting
            .dispatch(
                peer,
                Request::List {
                    after: None,
                    limit: 1,
                },
                deadline,
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while client.0.capacity() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("fill only waiting slot");
    let overflow = client
        .dispatch(
            peer,
            Request::List {
                after: None,
                limit: 1,
            },
            deadline,
        )
        .await;
    assert!(matches!(
        overflow,
        Err(Error::Api(ApiError {
            code: ErrorCode::QuotaExceeded,
            ..
        }))
    ));
    // The deadline expires while SQLite is busy, rather than waiting its five-second busy timeout.
    assert!(matches!(
        request.await.expect("request task"),
        Err(Error::Api(ApiError {
            code: ErrorCode::RequestTimeout,
            ..
        }))
    ));
    blocker.execute_batch("ROLLBACK").expect("release lock");
    drop(client);
    tokio::time::timeout(Duration::from_secs(1), worker)
        .await
        .expect("bounded shutdown")
        .expect("worker joined")
        .expect("expiry succeeded");
}

#[tokio::test]
async fn with_store_runs_callback_on_exclusive_worker() {
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("private directory");
    let path = dir.path().canonicalize().expect("canonical path");
    let config = handlers_tests::config(&path, vec![handlers_tests::runtime()]);
    let store =
        Store::open(&path, config.quotas.clone(), config.leases.clone(), 16).expect("store");
    let (client, worker) = start(store, Arc::new(config));
    let value = client
        .with_store(|store| Ok(store.list(1000, None, 1)?.len()))
        .await
        .expect("callback result");
    assert_eq!(value, 0);
    drop(client);
    worker.await.expect("worker joined").expect("worker result");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boot_journal_callback_inside_entered_runtime_does_not_nest_block_on() {
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("private directory");
    let path = dir.path().canonicalize().expect("canonical path");
    let config = handlers_tests::config(&path, vec![handlers_tests::runtime()]);
    let store =
        Store::open(&path, config.quotas.clone(), config.leases.clone(), 16).expect("store");
    let (client, worker) = start(store, Arc::new(config));
    let handle = tokio::runtime::Handle::current();
    let callback = client.clone();
    let value = tokio::task::spawn_blocking(move || {
        handle.block_on(async move {
            callback.with_store_blocking(|store| Ok(store.list(1000, None, 1)?.len()))
        })
    })
    .await
    .expect("boot worker did not panic")
    .expect("durable callback");
    assert_eq!(value, 0);
    drop(client);
    worker
        .await
        .expect("state worker joined")
        .expect("state worker result");
}

fn create_request(operation: &str, sandbox: &str) -> Request {
    Request::Mutate {
        operation: OperationId::with_sequence(1, operation).expect("operation"),
        operation_sequence: 1,
        mutation: Box::new(Mutation::Create {
            sandbox: SandboxId::new(sandbox).expect("sandbox"),
            expected_generation: None,
            spec: Box::new(handlers_tests::spec()),
            lease_seconds: 10,
        }),
    }
}

fn peer() -> Peer {
    Peer {
        uid: 1000,
        gid: 1000,
        pid: std::process::id(),
    }
}

#[tokio::test]
async fn timed_out_create_commits_once_and_replays_after_lock_release() {
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("tempdir");
    let path = dir.path().canonicalize().expect("canonical state path");
    let initial = handlers_tests::config(&path, vec![handlers_tests::runtime()]);
    let store =
        Store::open(&path, initial.quotas.clone(), initial.leases.clone(), 16).expect("store");
    let blocker = rusqlite::Connection::open(path.join("state.sqlite3")).expect("writer");
    blocker
        .execute_batch("BEGIN IMMEDIATE")
        .expect("hold writer lock");
    let (client, worker) = start(store, Arc::new(initial.clone()));
    let request = create_request("delayed-create", "delayed");
    let waiting = client.clone();
    let deadline = Instant::now() + Duration::from_millis(100);
    let result = tokio::spawn(async move { waiting.dispatch(peer(), request, deadline).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while client.0.capacity() != initial.daemon.max_connections as usize {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("worker dequeued blocked mutation");
    assert!(matches!(
        result.await.expect("request task"),
        Err(Error::Api(ApiError {
            code: ErrorCode::RequestTimeout,
            ..
        }))
    ));
    blocker
        .execute_batch("ROLLBACK")
        .expect("release writer lock");
    drop(client);
    tokio::time::timeout(Duration::from_secs(2), worker)
        .await
        .expect("worker drained")
        .expect("worker joined")
        .expect("worker succeeded");

    let removed_catalog = handlers_tests::config(&path, Vec::new());
    let mut reopened = Store::open(
        &path,
        removed_catalog.quotas.clone(),
        removed_catalog.leases.clone(),
        16,
    )
    .expect("reopen store");
    let replay = handlers::dispatch(
        &mut reopened,
        &removed_catalog,
        peer(),
        create_request("delayed-create", "delayed"),
    )
    .expect("same operation replays committed receipt");
    assert!(matches!(replay, Response::Sandbox(_)));
    let conflict = create_request("delayed-create", "different");
    assert!(matches!(
        handlers::dispatch(&mut reopened, &removed_catalog, peer(), conflict),
        Err(Error::Api(ApiError {
            code: ErrorCode::OperationConflict,
            ..
        }))
    ));
    let events = reopened.events(1000, 1, 16).expect("events");
    assert_eq!(events.events.len(), 1, "delayed commit must emit once");
}

#[tokio::test]
async fn expired_queued_mutation_is_discarded_without_receipt() {
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("tempdir");
    let path = dir.path().canonicalize().expect("canonical state path");
    let initial = handlers_tests::config(&path, vec![handlers_tests::runtime()]);
    let store =
        Store::open(&path, initial.quotas.clone(), initial.leases.clone(), 16).expect("store");
    let blocker = rusqlite::Connection::open(path.join("state.sqlite3")).expect("writer");
    blocker
        .execute_batch("BEGIN IMMEDIATE")
        .expect("hold writer lock");
    let (client, worker) = start(store, Arc::new(initial.clone()));
    client.expire().expect("queue expiry");
    tokio::time::timeout(Duration::from_secs(1), async {
        while client.0.capacity() != initial.daemon.max_connections as usize {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("worker dequeued blocked expiry");
    let request = create_request("expired-queued", "discarded");
    let deadline = Instant::now() + Duration::from_millis(100);
    let result = client.dispatch(peer(), request, deadline).await;
    assert!(matches!(
        result,
        Err(Error::Api(ApiError {
            code: ErrorCode::RequestTimeout,
            ..
        }))
    ));
    blocker
        .execute_batch("ROLLBACK")
        .expect("release writer lock");
    drop(client);
    tokio::time::timeout(Duration::from_secs(2), worker)
        .await
        .expect("worker drained")
        .expect("worker joined")
        .expect("worker succeeded");
    let reopened = Store::open(&path, initial.quotas, initial.leases, 16).expect("reopen store");
    assert!(matches!(
        reopened.inspect(1000, &SandboxId::new("discarded").expect("sandbox")),
        Err(Error::Api(ApiError {
            code: ErrorCode::SandboxNotFound,
            ..
        }))
    ));
    let operations: u32 = rusqlite::Connection::open(path.join("state.sqlite3"))
        .expect("database")
        .query_row("SELECT COUNT(*) FROM operations", [], |row| row.get(0))
        .expect("operation count");
    assert_eq!(
        operations, 0,
        "expired queued mutation must not create receipt"
    );
}
