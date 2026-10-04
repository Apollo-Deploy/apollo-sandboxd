use super::*;
use guest_protocol::{OutputPolicy, StdinMode};
use std::os::unix::fs::MetadataExt;
use std::sync::mpsc::sync_channel;
use std::time::Duration;

fn spec(id: &str, argv: Vec<String>) -> ExecutionSpec {
    let metadata = std::fs::metadata(".").expect("cwd metadata");
    ExecutionSpec {
        id: ExecId::new(id).expect("id"),
        argv,
        use_image_defaults: false,
        cwd: std::env::current_dir()
            .expect("cwd")
            .to_string_lossy()
            .into_owned(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        environment: Default::default(),
        secret_environment: Default::default(),
        pty: None,
        stdin: StdinMode::Closed,
        timeout_ms: 2_000,
        detached: false,
        output_policy: OutputPolicy::Disabled,
    }
}

#[test]
fn exact_argv_and_raw_output_are_preserved() {
    let (sender, receiver) = sync_channel(32);
    let mut manager = Manager::new(sender);
    manager
        .start(spec("exec", vec!["/usr/bin/printf".into(), "a\\0b".into()]))
        .expect("start");
    let mut bytes = Vec::new();
    let mut exited = false;
    for _ in 0..20 {
        match receiver
            .recv_timeout(Duration::from_millis(250))
            .expect("event")
        {
            GuestMessage::Output { record } => bytes.extend(record.payload),
            GuestMessage::ExecExit { .. } => {
                exited = true;
                break;
            }
            _ => {}
        }
    }
    assert!(exited);
    assert_eq!(bytes, b"a\0b");
}

#[test]
fn timeout_terminates_long_running_child() {
    let (sender, receiver) = sync_channel(32);
    let mut manager = Manager::new(sender);
    let mut value = spec(
        "timeout",
        vec!["/bin/sh".into(), "-c".into(), "sleep 2".into()],
    );
    value.timeout_ms = 20;
    manager.start(value).expect("start");
    let mut timed_out = false;
    for _ in 0..20 {
        if let GuestMessage::ExecExit {
            timed_out: value, ..
        } = receiver
            .recv_timeout(Duration::from_millis(250))
            .expect("event")
        {
            timed_out = value;
            break;
        }
    }
    assert!(timed_out);
}

#[cfg(target_os = "linux")]
#[test]
fn pty_child_has_a_controlling_terminal() {
    let (sender, receiver) = sync_channel(32);
    let mut manager = Manager::new(sender);
    let metadata = std::fs::metadata(".").expect("cwd metadata");
    let mut value = spec("pty", vec!["/usr/bin/tty".into()]);
    value.uid = metadata.uid();
    value.gid = metadata.gid();
    value.pty = Some(guest_protocol::TerminalSize {
        rows: 24,
        columns: 80,
    });
    manager.start(value).expect("start PTY");
    let mut output = Vec::new();
    let mut exited = false;
    for _ in 0..20 {
        match receiver
            .recv_timeout(Duration::from_millis(250))
            .expect("event")
        {
            GuestMessage::Output { record } => output.extend(record.payload),
            GuestMessage::ExecExit { .. } => {
                exited = true;
                break;
            }
            _ => {}
        }
    }
    assert!(exited);
    assert!(String::from_utf8_lossy(&output).contains("/dev/pts/"));
}

#[test]
fn completed_exec_id_cannot_be_reused() {
    let (sender, receiver) = sync_channel(32);
    let mut manager = Manager::new(sender);
    let value = spec("replay", vec!["/usr/bin/true".into()]);
    manager.start(value.clone()).expect("start");
    let exit = loop {
        if let GuestMessage::ExecExit { .. } = receiver
            .recv_timeout(Duration::from_millis(250))
            .expect("event")
        {
            break GuestMessage::ExecExit {
                exec: value.id.clone(),
                exit_code: Some(0),
                signal: None,
                timed_out: false,
            };
        }
    };
    manager.finish(&value.id, &exit);
    assert!(manager.start(value).is_err());
}

#[test]
fn completed_exec_can_be_explicitly_retired() {
    let (sender, receiver) = sync_channel(32);
    let mut manager = Manager::new(sender);
    let value = spec("retire", vec!["/usr/bin/true".into()]);
    manager.start(value.clone()).expect("start");
    let exit = loop {
        if let GuestMessage::ExecExit { .. } = receiver
            .recv_timeout(Duration::from_millis(250))
            .expect("event")
        {
            break GuestMessage::ExecExit {
                exec: value.id.clone(),
                exit_code: Some(0),
                signal: None,
                timed_out: false,
            };
        }
    };
    manager.finish(&value.id, &exit);
    manager.retire(&value.id).expect("retire");
    manager.start(value).expect("reuse after retirement");
}
