//! End-to-end daemon qualification over the public Unix socket protocol.
//!
//! This ignored test requires the explicit native qualification environment.
//! It starts the actual daemon binary and proves lifecycle behavior through
//! the same API used by the CLI.
use apollo_sandboxd::api::client;
use sandboxd_protocol::*;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[path = "native_api_contract/snapshot.rs"]
mod snapshot;
#[path = "native_api_contract/volume.rs"]
mod volume;

static OP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
use tokio::time::{Instant, sleep};

fn required(name: &str) -> String {
    let value = env::var(name).unwrap_or_else(|_| panic!("{name} is required"));
    assert!(!value.is_empty(), "{name} must not be empty");
    value
}

fn required_path(name: &str) -> PathBuf {
    let path = PathBuf::from(required(name));
    assert!(path.is_absolute(), "{name} must be absolute");
    path
}

fn unique(prefix: &str) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis();
    format!("{prefix}-{}-{millis}", std::process::id())
}

fn resource() -> Resources {
    Resources {
        vcpus: 1,
        memory_mib: 128,
        state_disk_mib: 64,
        host_memory_max_bytes: 268_435_456,
        cpu_quota_us: 100_000,
        cpu_period_us: 100_000,
        cpu_profile: None,
        cpuset: None,
        state_rate_limiter: None,
    }
}

fn sandbox_spec() -> SandboxSpec {
    SandboxSpec {
        architecture: if cfg!(target_arch = "aarch64") {
            Architecture::Aarch64
        } else {
            Architecture::X86_64
        },
        image: ImageDigest::new(format!("sha256:{}", required("APOLLO_NATIVE_BASE_DIGEST")))
            .expect("base digest"),
        kernel_profile: env::var("APOLLO_NATIVE_KERNEL_PROFILE")
            .unwrap_or_else(|_| "amazonlinux-microvm-x86".into()),
        runtime_profile: env::var("APOLLO_NATIVE_RUNTIME_PROFILE")
            .unwrap_or_else(|_| "fc-1-17-x86".into()),
        persistence: Persistence::FilesystemPersistent,
        resources: resource(),
        network: NetworkMode::None,
        volumes: Vec::new(),
        environment: Default::default(),
        lifetimes: Lifetimes {
            sandbox_ttl_seconds: 600,
            session_max_seconds: 600,
            idle_seconds: 300,
        },
    }
}

fn fence(record: &Sandbox) -> Fence {
    Fence {
        sandbox: record.id.clone(),
        generation: record.generation,
        session_generation: record.session.as_ref().map(|session| session.generation),
        lease: record.lease.id.clone(),
    }
}

async fn call(socket: &Path, operation: &str, mutation: Mutation) -> Response {
    let sequence = OP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    client::call(
        socket,
        &Request::Mutate {
            operation_sequence: sequence,
            operation: OperationId::with_sequence(sequence, operation).expect("operation id"),
            mutation: Box::new(mutation),
        },
        Duration::from_secs(120),
    )
    .await
    .unwrap_or_else(|error| panic!("API mutation {operation} failed: {error:?}"))
}

async fn initialize_operation_sequence(socket: &Path) {
    let response = client::call(
        socket,
        &Request::OperationWatermark,
        Duration::from_secs(10),
    )
    .await
    .expect("operation watermark");
    let Response::OperationWatermark { accepted_sequence } = response else {
        panic!("operation watermark response: {response:?}");
    };
    OP_SEQUENCE.store(accepted_sequence.saturating_add(1), Ordering::Relaxed);
}

async fn inspect_until(
    socket: &Path,
    id: &SandboxId,
    expected: impl Fn(SandboxState) -> bool,
) -> Sandbox {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let response = client::call(
            socket,
            &Request::Inspect {
                sandbox: id.clone(),
            },
            Duration::from_secs(10),
        )
        .await
        .expect("inspect sandbox");
        let Response::Sandbox(record) = response else {
            panic!("inspect did not return sandbox");
        };
        if expected(record.state) {
            return *record;
        }
        assert!(
            Instant::now() < deadline,
            "sandbox state timeout: {:?}",
            record.state
        );
        sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_socket(path: &Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().expect("daemon wait status") {
            panic!("daemon exited before readiness: {status}");
        }
        if path.exists() {
            if let Ok(stream) = tokio::net::UnixStream::connect(path).await {
                if let Some(peer_pid) = socket_peer_pid(&stream) {
                    assert_eq!(
                        peer_pid,
                        child.id() as i32,
                        "socket served by unexpected daemon"
                    );
                }
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "daemon socket did not appear: {path:?}"
        );
        sleep(Duration::from_millis(50)).await;
    }
}

#[cfg(target_os = "linux")]
fn socket_peer_pid(stream: &tokio::net::UnixStream) -> Option<i32> {
    rustix::net::sockopt::socket_peercred(stream)
        .ok()
        .map(|peer| peer.pid.as_raw_pid())
}

#[cfg(not(target_os = "linux"))]
fn socket_peer_pid(_stream: &tokio::net::UnixStream) -> Option<i32> {
    None
}

fn verify_provenance(binary: &Path) -> String {
    let revision = required("APOLLO_NATIVE_SOURCE_REVISION");
    assert!(!revision.contains(' '), "source revision must be a token");
    let bytes = fs::read(binary).expect("daemon binary");
    let digest = hex::encode(Sha256::digest(bytes));
    if let Ok(expected) = env::var("APOLLO_NATIVE_DAEMON_SHA256") {
        assert_eq!(digest, expected, "daemon binary provenance mismatch");
    }
    digest
}

fn stage(file: &mut impl Write, name: &str) {
    writeln!(file, "stage={name}").expect("qualification evidence write");
    file.flush().expect("qualification evidence flush");
}

fn start_daemon(binary: &Path, config: &Path, log: &Path) -> Child {
    Command::new(binary)
        .args(["--config", config.to_str().expect("config path")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(log)
                .expect("daemon log"),
        )
        .spawn()
        .expect("start actual daemon binary")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native Linux/KVM qualification; requires the pinned host assets and root privileges"]
async fn native_public_api_lifecycle_and_daemon_restart() {
    let binary = env::var_os("APOLLO_NATIVE_DAEMON_BIN")
        .map(PathBuf::from)
        .or_else(|| env::var_os("CARGO_BIN_EXE_apollo-sandboxd").map(PathBuf::from))
        .or_else(|| {
            Some(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/debug/apollo-sandboxd"))
        })
        .expect("APOLLO_NATIVE_DAEMON_BIN or CARGO_BIN_EXE_apollo-sandboxd is required");
    assert!(binary.is_absolute(), "daemon binary path must be absolute");
    let config = required_path("APOLLO_NATIVE_API_CONFIG");
    let socket = required_path("APOLLO_NATIVE_API_SOCKET");
    let evidence = required_path("APOLLO_NATIVE_API_EVIDENCE");
    let daemon_sha256 = verify_provenance(&binary);
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&evidence)
        .expect("qualification evidence");
    writeln!(
        file,
        "source_revision={}",
        required("APOLLO_NATIVE_SOURCE_REVISION")
    )
    .expect("evidence write");
    writeln!(file, "daemon_sha256={}", daemon_sha256).expect("evidence write");

    let log = evidence.with_extension("daemon.log");
    stage(&mut file, "daemon_start_1");
    let mut daemon = start_daemon(&binary, &config, &log);
    wait_socket(&socket, &mut daemon).await;
    stage(&mut file, "daemon_ready_1");
    initialize_operation_sequence(&socket).await;
    stage(&mut file, "operation_watermark_1");
    let sandbox = SandboxId::new(unique("native-api")).expect("sandbox id");
    stage(&mut file, "create");
    let create = call(
        &socket,
        "native-api-create",
        Mutation::Create {
            sandbox: sandbox.clone(),
            expected_generation: None,
            spec: Box::new(sandbox_spec()),
            lease_seconds: 600,
        },
    )
    .await;
    let Response::Sandbox(record) = create else {
        panic!("create did not return sandbox");
    };
    let start = call(
        &socket,
        "native-api-start-1",
        Mutation::Session {
            fence: fence(&record),
            control: SessionControl::Start,
        },
    )
    .await;
    stage(&mut file, "start_1");
    assert!(
        matches!(start, Response::Sandbox(_)),
        "start response: {start:?}"
    );
    let running = inspect_until(&socket, &sandbox, |state| {
        matches!(state, SandboxState::GuestReady | SandboxState::Running)
    })
    .await;
    let paused = call(
        &socket,
        "native-api-pause",
        Mutation::Session {
            fence: fence(&running),
            control: SessionControl::Pause,
        },
    )
    .await;
    stage(&mut file, "pause");
    assert!(
        matches!(paused, Response::Sandbox(_)),
        "pause response: {paused:?}"
    );
    let paused = inspect_until(&socket, &sandbox, |state| state == SandboxState::Paused).await;
    let resumed = call(
        &socket,
        "native-api-resume",
        Mutation::Session {
            fence: fence(&paused),
            control: SessionControl::Resume,
        },
    )
    .await;
    stage(&mut file, "resume");
    assert!(
        matches!(resumed, Response::Sandbox(_)),
        "resume response: {resumed:?}"
    );
    let running = inspect_until(&socket, &sandbox, |state| state == SandboxState::Running).await;

    let running = if env::var("APOLLO_NATIVE_SNAPSHOT_QUALIFY").as_deref() == Ok("1") {
        snapshot::qualify(
            &socket,
            running,
            &mut daemon,
            &binary,
            &config,
            &log,
            &mut file,
        )
        .await
    } else {
        stage(&mut file, "snapshot_not_requested");
        running
    };

    stage(&mut file, "daemon_sigkill");
    daemon.kill().expect("SIGKILL daemon");
    let _ = daemon.wait().expect("daemon wait");
    stage(&mut file, "daemon_start_2");
    let mut daemon = start_daemon(&binary, &config, &log);
    wait_socket(&socket, &mut daemon).await;
    stage(&mut file, "daemon_ready_2");
    initialize_operation_sequence(&socket).await;
    stage(&mut file, "operation_watermark_2");
    let recovered = inspect_until(&socket, &sandbox, |state| {
        matches!(state, SandboxState::GuestReady | SandboxState::Running)
    })
    .await;
    assert_eq!(recovered.generation, running.generation);
    let stopped = call(
        &socket,
        "native-api-stop-1",
        Mutation::Session {
            fence: fence(&recovered),
            control: SessionControl::Stop,
        },
    )
    .await;
    stage(&mut file, "stop_1");
    assert!(
        matches!(stopped, Response::Sandbox(_)),
        "stop response: {stopped:?}"
    );
    let stopped = inspect_until(&socket, &sandbox, |state| state == SandboxState::Stopped).await;
    assert!(
        stopped.session.is_none(),
        "stopped sandbox retained session"
    );
    let started_again = call(
        &socket,
        "native-api-start-2",
        Mutation::Session {
            fence: fence(&stopped),
            control: SessionControl::Start,
        },
    )
    .await;
    stage(&mut file, "start_2");
    assert!(matches!(started_again, Response::Sandbox(_)));
    let restarted = inspect_until(&socket, &sandbox, |state| {
        matches!(state, SandboxState::GuestReady | SandboxState::Running)
    })
    .await;
    assert!(
        restarted
            .session
            .as_ref()
            .expect("restarted session")
            .generation
            > running
                .session
                .as_ref()
                .expect("running session")
                .generation
    );
    let final_stop = call(
        &socket,
        "native-api-stop-2",
        Mutation::Session {
            fence: fence(&restarted),
            control: SessionControl::Stop,
        },
    )
    .await;
    stage(&mut file, "stop_2");
    assert!(matches!(final_stop, Response::Sandbox(_)));
    inspect_until(&socket, &sandbox, |state| state == SandboxState::Stopped).await;
    if env::var("APOLLO_NATIVE_VOLUME_QUALIFY").as_deref() == Ok("1") {
        volume::qualify(&socket, &mut daemon, &binary, &config, &log, &mut file).await;
    } else {
        stage(&mut file, "dynamic_volume_qualification_not_requested");
    }

    let _ = daemon.kill();
    let _ = daemon.wait();
}
