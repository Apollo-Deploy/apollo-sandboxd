//! Opt-in native proof of encrypted memory, disk and exec continuity through the public API.
use super::*;
use sandboxd_protocol::{
    exec::{ExecOutputItem, ExecutionSpec, OutputPolicy, StdinMode},
    files::FileRequest,
};

async fn guest(socket: &Path, sandbox: &Sandbox, command: GuestCommand) -> GuestReply {
    let sequence = OP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let response = client::call(
        socket,
        &Request::Guest {
            operation: OperationId::with_sequence(sequence, "native-snapshot-guest").unwrap(),
            operation_sequence: sequence,
            fence: fence(sandbox),
            command: Box::new(command),
        },
        Duration::from_secs(120),
    )
    .await
    .expect("snapshot guest operation");
    let Response::Guest(reply) = response else {
        panic!("guest response: {response:?}")
    };
    reply
}
async fn snapshot(socket: &Path, command: SnapshotCommand) -> Response {
    let sequence = OP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    client::call(
        socket,
        &Request::Snapshot {
            operation: OperationId::with_sequence(sequence, "native-snapshot").unwrap(),
            operation_sequence: sequence,
            command: Box::new(command),
        },
        Duration::from_secs(120),
    )
    .await
    .expect("public snapshot operation")
}
async fn write(socket: &Path, sandbox: &Sandbox, path: &str, data: &[u8]) {
    let reply = guest(
        socket,
        sandbox,
        GuestCommand::File {
            request: FileRequest::Write {
                transfer_id: unique("snapshot-write"),
                path: path.into(),
                offset: 0,
                data: data.to_vec(),
                final_chunk: true,
                sha256: Some(Sha256::digest(data).into()),
                atomic_replace: true,
            },
        },
    )
    .await;
    assert!(
        matches!(reply, GuestReply::File { .. }),
        "write reply: {reply:?}"
    );
}
async fn output(
    socket: &Path,
    sandbox: &Sandbox,
    exec: &ExecId,
) -> sandboxd_protocol::exec::ExecOutputPage {
    let reply = guest(
        socket,
        sandbox,
        GuestCommand::ExecReplay {
            exec: exec.clone(),
            from_sequence: 1,
            limit: 256,
        },
    )
    .await;
    let GuestReply::ExecOutput(page) = reply else {
        panic!("replay response: {reply:?}")
    };
    page
}
fn payload(page: &sandboxd_protocol::exec::ExecOutputPage) -> Vec<u8> {
    page.items
        .iter()
        .filter_map(|item| match item {
            ExecOutputItem::Record(record) => Some(record.payload.as_slice()),
            _ => None,
        })
        .flatten()
        .copied()
        .collect()
}

pub(super) async fn qualify(
    socket: &Path,
    initial: Sandbox,
    daemon: &mut Child,
    binary: &Path,
    config: &Path,
    log: &Path,
    evidence: &mut impl Write,
) -> Sandbox {
    stage(evidence, "snapshot_live_exec_start");
    let exec = ExecId::new(unique("snapshot-live")).unwrap();
    let marker = unique("memory-marker");
    let script = format!(
        "value='{marker}'; printf captured > /snapshot-proof; printf 'READY:%s\\n' \"$value\"; \
         while [ ! -f /snapshot-release ]; do sleep 0.1; done; \
         [ \"$(cat /snapshot-proof)\" = captured ] || exit 72; printf 'RESTORED:%s\\n' \"$value\""
    );
    let reply = guest(
        socket,
        &initial,
        GuestCommand::ExecStart {
            spec: Box::new(ExecutionSpec {
                id: exec.clone(),
                argv: vec![
                    env::var("APOLLO_NATIVE_SNAPSHOT_SHELL").unwrap_or_else(|_| "/bin/sh".into()),
                    "-c".into(),
                    script,
                ],
                use_image_defaults: false,
                cwd: "/".into(),
                uid: 0,
                gid: 0,
                supplementary_groups: Vec::new(),
                readonly_root: false,
                mounts: Vec::new(),
                max_processes: 64,
                environment: Default::default(),
                secret_environment: Default::default(),
                pty: None,
                stdin: StdinMode::Closed,
                timeout_ms: 300_000,
                detached: true,
                output_policy: OutputPolicy::BestEffort,
                output_bytes: 0,
            }),
        },
    )
    .await;
    assert!(
        matches!(reply, GuestReply::Acknowledged),
        "exec reply: {reply:?}"
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let page = output(socket, &initial, &exec).await;
        if String::from_utf8_lossy(&payload(&page)).contains(&format!("READY:{marker}")) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "exec never reached checkpoint barrier"
        );
        sleep(Duration::from_millis(100)).await;
    }
    let first = SnapshotId::new(unique("snapshot-create")).unwrap();
    let second = SnapshotId::new(unique("snapshot-suspend")).unwrap();
    stage(evidence, "snapshot_create");
    assert!(matches!(
        snapshot(
            socket,
            SnapshotCommand::Create {
                id: first.clone(),
                fence: fence(&initial),
                secret_policy: SnapshotSecretPolicy::Reject
            }
        )
        .await,
        Response::Snapshot(_)
    ));
    // Change the live disk after capture. Restore must select its paired disk copy.
    write(
        socket,
        &initial,
        "/snapshot-proof",
        b"changed-after-capture",
    )
    .await;
    assert!(matches!(
        call(
            socket,
            "snapshot-stop-source",
            Mutation::Session {
                fence: fence(&initial),
                control: SessionControl::Stop
            }
        )
        .await,
        Response::Sandbox(_)
    ));
    let stopped = inspect_until(socket, &initial.id, |state| state == SandboxState::Stopped).await;
    stage(evidence, "snapshot_restore_create");
    assert!(matches!(
        snapshot(
            socket,
            SnapshotCommand::Restore {
                id: first.clone(),
                fence: fence(&stopped)
            }
        )
        .await,
        Response::Snapshot(_)
    ));
    let restored = inspect_until(socket, &initial.id, |state| state == SandboxState::Running).await;
    assert!(
        restored.session.as_ref().unwrap().generation
            > initial.session.as_ref().unwrap().generation
    );
    let reply = guest(
        socket,
        &restored,
        GuestCommand::File {
            request: FileRequest::Read {
                path: "/snapshot-proof".into(),
                offset: 0,
                limit: 64,
            },
        },
    )
    .await;
    assert!(matches!(reply, GuestReply::File { data, .. } if data == b"captured"));
    stage(evidence, "snapshot_suspend");
    assert!(matches!(
        snapshot(
            socket,
            SnapshotCommand::Suspend {
                id: second.clone(),
                fence: fence(&restored),
                secret_policy: SnapshotSecretPolicy::Reject
            }
        )
        .await,
        Response::Snapshot(_)
    ));
    let suspended = inspect_until(socket, &initial.id, |state| {
        state == SandboxState::Suspended
    })
    .await;
    assert!(suspended.session.is_none());
    stage(evidence, "snapshot_daemon_restart_while_suspended");
    daemon.kill().expect("snapshot daemon kill");
    daemon.wait().expect("snapshot daemon wait");
    *daemon = start_daemon(binary, config, log);
    wait_socket(socket, daemon).await;
    initialize_operation_sequence(socket).await;
    stage(evidence, "snapshot_restore_suspend");
    assert!(matches!(
        snapshot(
            socket,
            SnapshotCommand::Restore {
                id: second.clone(),
                fence: fence(&suspended)
            }
        )
        .await,
        Response::Snapshot(_)
    ));
    let resumed = inspect_until(socket, &initial.id, |state| state == SandboxState::Running).await;
    assert!(
        resumed.session.as_ref().unwrap().generation
            > restored.session.as_ref().unwrap().generation
    );
    write(socket, &resumed, "/snapshot-release", b"release").await;
    let reply = guest(
        socket,
        &resumed,
        GuestCommand::ExecWait { exec: exec.clone() },
    )
    .await;
    assert!(
        matches!(
            reply,
            GuestReply::ExecExit {
                exit_code: Some(0),
                signal: None,
                timed_out: false,
                ..
            }
        ),
        "restored process: {reply:?}"
    );
    let page = output(socket, &resumed, &exec).await;
    let bytes = payload(&page);
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        text.contains(&format!("READY:{marker}")) && text.contains(&format!("RESTORED:{marker}")),
        "restored output: {text}"
    );
    assert!(
        !page.transport_gaps.is_empty(),
        "restore must expose transport gap"
    );
    for id in [first, second] {
        assert!(matches!(
            snapshot(
                socket,
                SnapshotCommand::Delete {
                    id,
                    fence: fence(&resumed)
                }
            )
            .await,
            Response::SnapshotDeleted { .. }
        ));
    }
    stage(evidence, "snapshot_full_memory_disk_exec_restore_pass");
    resumed
}
