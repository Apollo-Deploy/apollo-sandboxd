#![allow(dead_code)]
pub mod historical;
use apollo_sandboxd::{
    config::{LeaseConfig, Quotas},
    state::Store,
};
use sandboxd_protocol::*;
use std::{collections::BTreeMap, os::unix::fs::PermissionsExt, path::Path};

pub fn directory() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("private directory")
}

pub fn quotas() -> Quotas {
    Quotas {
        max_active_sandboxes: 16,
        max_booting_sandboxes: 4,
        max_sandbox_identities: 1024,
        max_operation_receipts: 4096,
        max_vcpus: 4,
        max_memory_mib: 1024,
        max_state_disk_mib: 1024,
    }
}
pub fn open(path: &Path, events: u32) -> Store {
    Store::open(path, quotas(), LeaseConfig { max_seconds: 3600 }, events)
        .expect("open real SQLite store")
}
pub fn spec() -> SandboxSpec {
    // Identity metadata fixture only: no assertion claims an image was imported or booted.
    SandboxSpec {
        architecture: Architecture::Aarch64,
        image: ImageDigest::new(format!("sha256:{}", "a".repeat(64))).expect("digest"),
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
        volumes: Vec::new(),
        environment: BTreeMap::new(),
        lifetimes: Lifetimes {
            sandbox_ttl_seconds: 3600,
            session_max_seconds: 1800,
            idle_seconds: 300,
        },
    }
}
pub fn create(id: &str, previous: Option<SandboxGeneration>) -> Mutation {
    Mutation::Create {
        sandbox: SandboxId::new(id).expect("id"),
        expected_generation: previous,
        spec: Box::new(spec()),
        lease_seconds: 10,
    }
}
pub fn op(id: &str) -> OperationId {
    OperationId::new(id).expect("operation")
}
pub fn sandbox(response: Response) -> Sandbox {
    let record = match response {
        Response::Sandbox(record) => Some(*record),
        _ => None,
    };
    record.expect("expected sandbox response")
}
pub fn fence(record: &Sandbox) -> Fence {
    Fence {
        sandbox: record.id.clone(),
        generation: record.generation,
        session_generation: record.session.as_ref().map(|s| s.generation),
        lease: record.lease.id.clone(),
    }
}
