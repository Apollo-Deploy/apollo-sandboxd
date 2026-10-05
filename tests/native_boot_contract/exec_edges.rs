use super::*;

pub async fn run(guest: &apollo_sandboxd::guest::GuestConnection) {
    let chown_exec = ExecId::new("native-root-chown").unwrap();
    let chown_start = guest
        .request(
            OperationId::new("native-root-chown-start").unwrap(),
            GuestMessage::ExecStart {
                spec: Box::new(ExecutionSpec {
                    id: chown_exec,
                    argv: vec![
                        "/bin/sh".into(),
                        "-c".into(),
                        "f=/tmp/apollo-native-chown; : > \"$f\" && chown 1234:1234 \"$f\" && test \"$(stat -c %u:%g \"$f\")\" = 1234:1234 && echo root-chown-preserved".into(),
                    ],
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
                    timeout_ms: 10_000,
                    detached: false,
                    output_policy: OutputPolicy::Required,
                    output_bytes: 256 << 20,
                }),
            },
        )
        .await
        .expect("guest root chown request");
    assert!(matches!(chown_start.message, GuestMessage::Ready));
    let mut chown_output = Vec::new();
    let chown_exit = loop {
        match guest
            .receive(Duration::from_secs(10))
            .await
            .expect("root chown event")
            .message
        {
            GuestMessage::Output { record } => chown_output.extend(record.payload),
            GuestMessage::ExecExit {
                exit_code,
                signal,
                timed_out,
                ..
            } => break (exit_code, signal, timed_out),
            _ => {}
        }
    };
    assert_eq!(chown_exit, (Some(0), None, false));
    assert!(
        String::from_utf8_lossy(&chown_output).contains("root-chown-preserved"),
        "uid 0 could not change a file's numeric owner: {chown_output:?}"
    );

    let cancel_exec = ExecId::new("native-cancel-descendant").unwrap();
    let cancel_start = guest
        .request(
            OperationId::new("native-cancel-descendant-start").unwrap(),
            GuestMessage::ExecStart {
                spec: Box::new(ExecutionSpec {
                    id: cancel_exec.clone(),
                    argv: vec![
                        "/bin/sh".into(),
                        "-c".into(),
                        "sleep 120 & child=$!; printf 'cancel-descendant-ready:%s\\n' \"$child\"; wait \"$child\"".into(),
                    ],
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
                    timeout_ms: 120_000,
                    detached: false,
                    output_policy: OutputPolicy::Required,
                    output_bytes: 256 << 20,
                }),
            },
        )
        .await
        .expect("guest cancellable descendant request");
    assert!(matches!(cancel_start.message, GuestMessage::Ready));
    let mut cancel_output = Vec::new();
    loop {
        match guest
            .receive(Duration::from_secs(10))
            .await
            .expect("descendant readiness event")
            .message
        {
            GuestMessage::Output { record } => {
                cancel_output.extend(record.payload);
                if String::from_utf8_lossy(&cancel_output).contains("cancel-descendant-ready:") {
                    break;
                }
            }
            GuestMessage::ExecExit { .. } => panic!("cancellable exec exited before cancellation"),
            _ => {}
        }
    }
    let cancel_time = Instant::now();
    let cancel_ack = guest
        .request(
            OperationId::new("native-cancel-descendant-cancel").unwrap(),
            GuestMessage::ExecCancel { exec: cancel_exec },
        )
        .await
        .expect("guest descendant cancellation");
    assert!(matches!(cancel_ack.message, GuestMessage::Ready));
    let cancel_exit = loop {
        match guest
            .receive(Duration::from_secs(10))
            .await
            .expect("cancelled descendant cleanup event")
            .message
        {
            GuestMessage::Output { record } => cancel_output.extend(record.payload),
            GuestMessage::ExecExit {
                exit_code,
                signal,
                timed_out,
                ..
            } => break (exit_code, signal, timed_out),
            _ => {}
        }
    };
    assert!(
        cancel_time.elapsed() < Duration::from_secs(8),
        "cancellation waited for a descendant holding the output pipe"
    );
    assert_eq!(cancel_exit, (None, Some(9), false));
    let pty = ExecId::new("native-pty").unwrap();
    guest
        .request(
            OperationId::new("native-pty-start").unwrap(),
            GuestMessage::ExecStart {
                spec: Box::new(ExecutionSpec {
                    id: pty,
                    argv: vec![
                        "/bin/sh".into(),
                        "-c".into(),
                        "test -t 0 && printf native-pty-controlling-terminal".into(),
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
                    pty: Some(TerminalSize {
                        rows: 24,
                        columns: 80,
                    }),
                    stdin: StdinMode::Closed,
                    timeout_ms: 10_000,
                    detached: false,
                    output_policy: OutputPolicy::Required,
                    output_bytes: 256 << 20,
                }),
            },
        )
        .await
        .expect("guest PTY start");
    let mut pty_output = Vec::new();
    loop {
        match guest
            .receive(Duration::from_secs(10))
            .await
            .expect("PTY event")
            .message
        {
            GuestMessage::Output { record } => pty_output.extend(record.payload),
            GuestMessage::ExecExit {
                exit_code,
                signal,
                timed_out,
                ..
            } => {
                assert_eq!(exit_code, Some(0));
                assert_eq!(signal, None);
                assert!(!timed_out);
                break;
            }
            _ => {}
        }
    }
    assert!(String::from_utf8_lossy(&pty_output).contains("native-pty-controlling-terminal"));
}
