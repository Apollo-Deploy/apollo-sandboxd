//! Native Linux public-socket qualification for the Artifactd prepared-rootfs handoff.
#![cfg(target_os = "linux")]
use apollo_sandboxd::api::client;
use artifactd_protocol::{
    Action as ArtifactAction, OperationId as ArtifactOperationId, PreparedArtifactId,
    Request as ArtifactRequest, VERSION as ARTIFACTD_VERSION,
};
use sandboxd_protocol::{Architecture, ImageCommand, ImageDigest, OperationId, Request, Response};
use serde::Deserialize;
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::time::{Instant, sleep};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HandoffFacts {
    prepared_artifact_id: String,
    manifest_digest: String,
    consumer_lease_id: String,
    producer_lease_id: String,
    architecture: Architecture,
    producer_uid: u32,
    producer_gid: u32,
}

fn required_path(name: &str) -> PathBuf {
    let path = PathBuf::from(env::var_os(name).unwrap_or_else(|| panic!("{name} is required")));
    assert!(path.is_absolute(), "{name} must be absolute");
    path
}

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn daemon(binary: &Path, config: &Path, log: &Path) -> Daemon {
    Daemon(
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
            .expect("start isolated sandboxd"),
    )
}

async fn wait_ready(socket: &Path, process: &mut Daemon, log: &Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = process.0.try_wait().expect("daemon status") {
            let bytes = fs::read(log).unwrap_or_default();
            let start = bytes.len().saturating_sub(8192);
            panic!(
                "sandboxd exited before readiness: {status}; log tail: {}",
                String::from_utf8_lossy(&bytes[start..])
            );
        }
        if client::call(socket, &Request::Health, Duration::from_secs(2))
            .await
            .is_ok()
        {
            return;
        }
        assert!(Instant::now() < deadline, "sandboxd did not become ready");
        sleep(Duration::from_millis(50)).await;
    }
}

fn image_request(
    operation: OperationId,
    sequence: u64,
    facts: &HandoffFacts,
    lease: &str,
) -> Request {
    Request::Image {
        operation,
        operation_sequence: sequence,
        command: Box::new(ImageCommand::ImportPrepared {
            prepared_artifact_id: facts.prepared_artifact_id.clone(),
            manifest_digest: facts.manifest_digest.clone(),
            lease_id: lease.to_owned(),
            architecture: facts.architecture,
        }),
    }
}

async fn import_until_complete(socket: &Path, request: &Request) -> Response {
    let deadline = Instant::now() + Duration::from_secs(240);
    loop {
        match client::call(socket, request, Duration::from_secs(240)).await {
            Ok(Response::ImagePending { .. }) => {
                assert!(Instant::now() < deadline, "prepared image import timed out");
                sleep(Duration::from_millis(100)).await;
            }
            Ok(response) => return response,
            Err(error) => panic!("prepared image handoff failed: {error:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native Linux qualification; requires a staged Artifactd producer fixture and pinned formatter"]
async fn native_artifactd_handoff_persists_replays_and_releases_lease() {
    let binary = required_path("APOLLO_NATIVE_DAEMON_BIN");
    let config = required_path("APOLLO_NATIVE_API_CONFIG");
    let socket = required_path("APOLLO_NATIVE_API_SOCKET");
    let evidence = required_path("APOLLO_NATIVE_API_EVIDENCE");
    let facts_path = required_path("APOLLO_NATIVE_ARTIFACTD_HANDOFF_FACTS");
    let facts: HandoffFacts =
        serde_json::from_slice(&fs::read(&facts_path).expect("producer-persisted handoff facts"))
            .expect("valid producer handoff facts");
    assert!(facts.producer_uid != 0 && facts.producer_gid != 0);
    let digest = ImageDigest::new(facts.manifest_digest.clone()).expect("manifest digest");
    let log = evidence.with_extension("daemon.log");
    let mut evidence_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&evidence)
        .expect("qualification evidence");
    writeln!(evidence_file, "producer_uid={}", facts.producer_uid).expect("evidence write");
    writeln!(evidence_file, "producer_gid={}", facts.producer_gid).expect("evidence write");
    writeln!(
        evidence_file,
        "prepared_artifact_id={}",
        facts.prepared_artifact_id
    )
    .expect("evidence write");
    writeln!(evidence_file, "manifest_digest={}", facts.manifest_digest).expect("evidence write");

    let mut process = daemon(&binary, &config, &log);
    wait_ready(&socket, &mut process, &log).await;
    let denied_operation = OperationId::with_sequence(1, "wrong-grantee").expect("operation id");
    let denied = image_request(denied_operation, 1, &facts, &facts.producer_lease_id);
    assert!(
        client::call(&socket, &denied, Duration::from_secs(30))
            .await
            .is_err(),
        "sandboxd must reject a lease issued to the producer"
    );

    let operation = OperationId::with_sequence(2, "artifactd-handoff").expect("operation id");
    let request = image_request(operation.clone(), 2, &facts, &facts.consumer_lease_id);
    let Response::Image(info) = import_until_complete(&socket, &request).await else {
        panic!("prepared import did not return image metadata");
    };
    assert_eq!(info.digest, digest);
    assert_eq!(info.architecture, facts.architecture);
    assert_eq!(info.layers, 1);
    assert!(info.bytes > 0 && info.rootfs_sha256.len() == 64);
    writeln!(evidence_file, "rootfs_sha256={}", info.rootfs_sha256).expect("evidence write");
    writeln!(evidence_file, "rootfs_bytes={}", info.bytes).expect("evidence write");
    evidence_file.flush().expect("evidence flush");

    process.0.kill().expect("SIGKILL sandboxd");
    let _ = process.0.wait().expect("wait for sandboxd");
    let mut restarted = daemon(&binary, &config, &log);
    wait_ready(&socket, &mut restarted, &log).await;
    let Response::Image(replayed) = import_until_complete(&socket, &request).await else {
        panic!("replayed operation did not return image metadata");
    };
    assert_eq!(replayed, info, "replay after restart changed the receipt");
    let inspected = client::call(
        &socket,
        &Request::ImageInspect { digest },
        Duration::from_secs(30),
    )
    .await
    .expect("inspect durable prepared image");
    assert_eq!(inspected, Response::Image(info));

    let artifactd_socket = required_path("APOLLO_NATIVE_ARTIFACTD_SOCKET");
    let server_uid: u32 = env::var("APOLLO_NATIVE_ARTIFACTD_UID")
        .expect("Artifactd server UID")
        .parse()
        .expect("numeric Artifactd UID");
    let artifact_client = artifactd_protocol::client::Client::new(&artifactd_socket, server_uid);
    let operation_id: ArtifactOperationId = artifact_client.allocate().expect("allocate operation");
    let prepared: PreparedArtifactId = facts
        .prepared_artifact_id
        .clone()
        .try_into()
        .expect("prepared artifact ID");
    let lease = facts
        .consumer_lease_id
        .clone()
        .try_into()
        .expect("consumer lease ID");
    let (released, descriptor) = artifact_client
        .call(
            &ArtifactRequest {
                version: ARTIFACTD_VERSION,
                operation_id,
                action: ArtifactAction::OpenPrepared {
                    id: prepared,
                    lease,
                },
            },
            None,
        )
        .expect("query released delegated lease");
    assert!(descriptor.is_none());
    assert!(
        released.result.is_err(),
        "sandboxd must release the delegated lease"
    );
    writeln!(evidence_file, "consumer_lease_released=true").expect("evidence write");
    evidence_file.flush().expect("evidence flush");

    restarted.0.kill().expect("stop restarted sandboxd");
    let _ = restarted.0.wait().expect("wait for restarted sandboxd");
}
