use super::*;

pub async fn run(guest: &apollo_sandboxd::guest::GuestConnection) {
    let exec = ExecId::new("native-exec").unwrap();
    let ready = guest
        .request(
            OperationId::new("native-exec-start").unwrap(),
            GuestMessage::ExecStart {
                spec: Box::new(ExecutionSpec {
                    id: exec.clone(),
                    argv: vec![
                        "/bin/sh".into(),
                        "-c".into(),
                        "printf '%s|%s\\000%s' \"$1\" \"$2\" \"$3\"".into(),
                        "argv-test".into(),
                        "space arg".into(),
                        "quote'\"*".into(),
                        "tail".into(),
                    ],
                    use_image_defaults: false,
                    cwd: "/".into(),
                    uid: 0,
                    gid: 0,
                    supplementary_groups: Vec::new(),
                    readonly_root: false,
                    mounts: Vec::new(),
                    max_processes: 64,
                    environment: BTreeMap::new(),
                    secret_environment: BTreeMap::new(),
                    pty: None,
                    stdin: StdinMode::Closed,
                    timeout_ms: 10_000,
                    detached: false,
                    output_policy: OutputPolicy::Required,
                    output_bytes: 256 << 20,
                }),
            },
        )
        .await
        .expect("guest exec request");
    assert!(matches!(ready.message, GuestMessage::Ready));
    let mut output = Vec::new();
    loop {
        match guest
            .receive(Duration::from_secs(10))
            .await
            .expect("exec event")
        {
            peer if matches!(peer.message, GuestMessage::Output { .. }) => {
                if let GuestMessage::Output { record } = peer.message {
                    output.extend(record.payload);
                }
            }
            peer if matches!(peer.message, GuestMessage::ExecExit { .. }) => break,
            _ => {}
        }
    }
    assert_eq!(output, b"space arg|quote'\"*\0tail");

    let timeout = guest
        .request(
            OperationId::new("native-timeout-start").unwrap(),
            GuestMessage::ExecStart {
                spec: Box::new(ExecutionSpec {
                    id: ExecId::new("native-timeout").unwrap(),
                    argv: vec!["/bin/sleep".into(), "30".into()],
                    use_image_defaults: false,
                    cwd: "/".into(),
                    uid: 0,
                    gid: 0,
                    supplementary_groups: Vec::new(),
                    readonly_root: false,
                    mounts: Vec::new(),
                    max_processes: 4,
                    environment: BTreeMap::new(),
                    secret_environment: BTreeMap::new(),
                    pty: None,
                    stdin: StdinMode::Closed,
                    timeout_ms: 250,
                    detached: false,
                    output_policy: OutputPolicy::Required,
                    output_bytes: 256 << 20,
                }),
            },
        )
        .await
        .expect("timeout exec");
    assert!(matches!(timeout.message, GuestMessage::Ready));
    let timed_out = loop {
        match guest
            .receive(Duration::from_secs(5))
            .await
            .expect("timeout result")
            .message
        {
            GuestMessage::ExecExit {
                exec, timed_out, ..
            } if exec == ExecId::new("native-timeout").unwrap() => break timed_out,
            GuestMessage::Output { .. } => {}
            other => panic!("unexpected timeout event: {other:?}"),
        }
    };
    assert!(timed_out, "deadline expiry must be reported as timed_out");

    let reuse_id = ExecId::new("native-retire-reuse").unwrap();
    let first = guest
        .request(
            OperationId::new("native-retire-first").unwrap(),
            GuestMessage::ExecStart {
                spec: Box::new(ExecutionSpec {
                    id: reuse_id.clone(),
                    argv: vec!["/bin/sh".into(), "-c".into(), "exit 0".into()],
                    use_image_defaults: false,
                    cwd: "/".into(),
                    uid: 0,
                    gid: 0,
                    supplementary_groups: Vec::new(),
                    readonly_root: false,
                    mounts: Vec::new(),
                    max_processes: 4,
                    environment: BTreeMap::new(),
                    secret_environment: BTreeMap::new(),
                    pty: None,
                    stdin: StdinMode::Closed,
                    timeout_ms: 5000,
                    detached: false,
                    output_policy: OutputPolicy::Required,
                    output_bytes: 256 << 20,
                }),
            },
        )
        .await
        .expect("first ID start");
    assert!(matches!(first.message, GuestMessage::Ready));
    loop {
        match guest
            .receive(Duration::from_secs(5))
            .await
            .expect("first execution terminal event")
            .message
        {
            GuestMessage::ExecExit {
                exec,
                exit_code: Some(0),
                timed_out: false,
                ..
            } if exec == reuse_id => break,
            GuestMessage::ExecExit { exec, .. } if exec == reuse_id => {
                panic!("first execution failed before ID reservation check")
            }
            _ => {}
        }
    }
    let mut completed = false;
    for attempt in 0..20 {
        let observation = guest
            .request(
                OperationId::new(format!("native-retire-wait-{attempt}")).unwrap(),
                GuestMessage::ExecWait {
                    exec: reuse_id.clone(),
                },
            )
            .await
            .expect("read first ID terminal receipt");
        match observation.message {
            GuestMessage::ExecExit {
                exit_code: Some(0),
                timed_out: false,
                ..
            } => {
                completed = true;
                break;
            }
            GuestMessage::Ready => tokio::time::sleep(Duration::from_millis(25)).await,
            other => panic!("first execution terminal receipt was invalid: {other:?}"),
        }
    }
    assert!(
        completed,
        "first execution must have a durable terminal receipt before its ID is rejected"
    );
    let duplicate = guest
        .request(
            OperationId::new("native-retire-duplicate").unwrap(),
            GuestMessage::ExecStart {
                spec: Box::new(ExecutionSpec {
                    id: reuse_id.clone(),
                    argv: vec!["/bin/sh".into(), "-c".into(), "exit 0".into()],
                    use_image_defaults: false,
                    cwd: "/".into(),
                    uid: 0,
                    gid: 0,
                    supplementary_groups: Vec::new(),
                    readonly_root: false,
                    mounts: Vec::new(),
                    max_processes: 4,
                    environment: BTreeMap::new(),
                    secret_environment: BTreeMap::new(),
                    pty: None,
                    stdin: StdinMode::Closed,
                    timeout_ms: 5000,
                    detached: false,
                    output_policy: OutputPolicy::Required,
                    output_bytes: 256 << 20,
                }),
            },
        )
        .await
        .expect("duplicate ID response");
    assert!(
        matches!(duplicate.message, GuestMessage::Error { .. }),
        "completed ID remains reserved until retirement: {:?}",
        duplicate.message
    );
    let retired = guest
        .request(
            OperationId::new("native-retire-release").unwrap(),
            GuestMessage::RetireExec {
                exec: reuse_id.clone(),
            },
        )
        .await
        .expect("retire completed ID");
    assert!(matches!(retired.message, GuestMessage::Ready));
    let reused = guest
        .request(
            OperationId::new("native-retire-reuse-start").unwrap(),
            GuestMessage::ExecStart {
                spec: Box::new(ExecutionSpec {
                    id: reuse_id,
                    argv: vec!["/bin/sh".into(), "-c".into(), "exit 0".into()],
                    use_image_defaults: false,
                    cwd: "/".into(),
                    uid: 0,
                    gid: 0,
                    supplementary_groups: Vec::new(),
                    readonly_root: false,
                    mounts: Vec::new(),
                    max_processes: 4,
                    environment: BTreeMap::new(),
                    secret_environment: BTreeMap::new(),
                    pty: None,
                    stdin: StdinMode::Closed,
                    timeout_ms: 5000,
                    detached: false,
                    output_policy: OutputPolicy::Required,
                    output_bytes: 256 << 20,
                }),
            },
        )
        .await
        .expect("reuse retired ID");
    assert!(matches!(reused.message, GuestMessage::Ready));
    loop {
        match guest
            .receive(Duration::from_secs(5))
            .await
            .expect("reused exec terminal event")
            .message
        {
            GuestMessage::ExecExit {
                exec,
                exit_code: Some(0),
                ..
            } if exec == ExecId::new("native-retire-reuse").unwrap() => break,
            GuestMessage::ExecExit { exec, .. }
                if exec == ExecId::new("native-retire-reuse").unwrap() =>
            {
                panic!("reused exec did not complete successfully")
            }
            _ => {}
        }
    }
}
