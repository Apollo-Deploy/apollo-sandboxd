use crate::{
    api::handlers::dispatch,
    config::{
        Config, Daemon, IdentityPools, KernelProfile, LeaseConfig, Quotas, RuntimeProfile,
        Security, State,
    },
    security::peer::Peer,
    state::Store,
};
use sandboxd_protocol::*;
use std::{collections::BTreeMap, os::unix::fs::PermissionsExt, path::PathBuf};

pub(super) fn config(state: &std::path::Path, runtimes: Vec<RuntimeProfile>) -> Config {
    Config {
        snapshots: None,
        checkpoints: Default::default(),
        execution: None,
        daemon: Daemon {
            socket: state.join("sandboxd.sock"),
            socket_group: 0,
            max_connections: 4,
            request_timeout_seconds: 5,
        },
        security: Security {
            allowed_uids: vec![1000],
            allowed_gids: Vec::new(),
            allowed_pids: Vec::new(),
        },
        state: State {
            directory: state.to_path_buf(),
            event_retention: 16,
        },
        runtimes,
        kernels: vec![KernelProfile {
            name: "kernel".into(),
            architecture: Architecture::X86_64,
            kernel: PathBuf::from("/unused/kernel"),
            kernel_sha256: "0".repeat(64),
            initramfs: PathBuf::from("/unused/initramfs"),
            initramfs_sha256: "0".repeat(64),
        }],
        identities: IdentityPools {
            uid_first: 100_000,
            uid_last: 100_100,
            gid_first: 100_000,
            gid_last: 100_100,
            cid_first: 3,
            cid_last: 100,
        },
        quotas: Quotas {
            max_active_sandboxes: 16,
            max_booting_sandboxes: 4,
            max_sandbox_identities: 8,
            max_operation_receipts: 16,
            max_vcpus: 2,
            max_memory_mib: 256,
            max_state_disk_mib: 256,
        },
        leases: LeaseConfig { max_seconds: 60 },
        volume_catalog: Default::default(),
    }
}

pub(super) fn runtime() -> RuntimeProfile {
    RuntimeProfile {
        name: "runtime".into(),
        version: "1.17.0".into(),
        architecture: Architecture::X86_64,
        firecracker: PathBuf::from("/unused/firecracker"),
        firecracker_sha256: "0".repeat(64),
        jailer: PathBuf::from("/unused/jailer"),
        jailer_sha256: "0".repeat(64),
    }
}

pub(super) fn spec() -> SandboxSpec {
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

#[test]
fn committed_create_replay_is_idempotent_when_catalog_changes() {
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("tempdir");
    let path = dir.path().canonicalize().expect("canonical state path");
    let initial = config(&path, vec![runtime()]);
    let mut store =
        Store::open(&path, initial.quotas.clone(), initial.leases.clone(), 16).expect("store");
    let request = Request::Mutate {
        operation: OperationId::with_sequence(1, "create-replay").expect("operation"),
        operation_sequence: 1,
        mutation: Box::new(Mutation::Create {
            sandbox: SandboxId::new("replay").expect("sandbox"),
            expected_generation: None,
            spec: Box::new(spec()),
            lease_seconds: 10,
        }),
    };
    let peer = Peer {
        uid: 1000,
        gid: 1000,
        pid: std::process::id(),
    };
    let first = dispatch(&mut store, &initial, peer, request.clone()).expect("initial create");
    let removed_catalog = config(&path, Vec::new());
    let retry = dispatch(&mut store, &removed_catalog, peer, request).expect("idempotent replay");
    assert_eq!(retry, first);
}

#[test]
fn operation_inspection_dispatch_uses_peer_ownership_and_does_not_advance_sequence() {
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let path = dir.path().canonicalize().unwrap();
    let config = config(&path, vec![runtime()]);
    let mut store = Store::open(&path, config.quotas.clone(), config.leases.clone(), 16).unwrap();
    let peer = Peer {
        uid: 1000,
        gid: 1000,
        pid: std::process::id(),
    };
    let operation = OperationId::with_sequence(1, "receipt-route").unwrap();
    let created = dispatch(
        &mut store,
        &config,
        peer,
        Request::Mutate {
            operation: operation.clone(),
            operation_sequence: 1,
            mutation: Box::new(Mutation::Create {
                sandbox: SandboxId::new("receipt-route").unwrap(),
                expected_generation: None,
                spec: Box::new(spec()),
                lease_seconds: 10,
            }),
        },
    )
    .unwrap();
    let request = Request::OperationInspect {
        operation,
        operation_sequence: 1,
    };
    let Response::OperationReceipt(receipt) =
        dispatch(&mut store, &config, peer, request.clone()).unwrap()
    else {
        panic!("inspection response");
    };
    assert_eq!(receipt.state, OperationReceiptState::Complete);
    assert_eq!(receipt.response.as_deref(), Some(&created));
    let foreign = Peer { uid: 2000, ..peer };
    let Response::OperationReceipt(receipt) =
        dispatch(&mut store, &config, foreign, request).unwrap()
    else {
        panic!("inspection response");
    };
    assert_eq!(receipt.state, OperationReceiptState::Unknown);
    assert!(receipt.response.is_none());
    assert_eq!(store.operation_watermark(1000).unwrap(), 1);
    assert_eq!(store.operation_watermark(2000).unwrap(), 0);
}
