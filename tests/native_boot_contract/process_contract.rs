use super::*;

pub async fn run(guest: &apollo_sandboxd::guest::GuestConnection) {
    let process_view = ExecId::new("native-process-view").unwrap();
    let process_view_start = guest
        .request(
            OperationId::new("native-process-view-start").unwrap(),
            GuestMessage::ExecStart {
                spec: Box::new(ExecutionSpec {
                    id: process_view,
                    argv: vec![
                        "/bin/sh".into(),
                        "-c".into(),
                        r#"result=0
if [ -e /sys/fs/cgroup ]; then echo cgroup-controls-visible; result=1; fi
for device in /dev/*; do if [ -b "$device" ]; then echo block-device-visible:$device; result=1; fi; done
if [ -e /proc/sysrq-trigger ] && [ -w /proc/sysrq-trigger ]; then echo sysrq-trigger-writable; result=1; fi
if [ -e /proc/sys/kernel/sysrq ] && [ -w /proc/sys/kernel/sysrq ]; then echo sysrq-setting-writable; result=1; fi
if [ -w /proc/sys ] || [ -w /proc/sys/kernel ]; then echo proc-sys-controls-writable; result=1; fi
sys_mount=
while IFS= read -r mount_line; do case "$mount_line" in *" /sys "*) sys_mount=$mount_line;; esac; done < /proc/self/mountinfo
case "$sys_mount" in *" /sys ro,"*" - tmpfs "*) ;; *) echo sysfs-not-private-readonly-tmpfs; result=1;; esac
for path in /sys/* /sys/.[!.]* /sys/..?*; do if [ -e "$path" ] || [ -L "$path" ]; then echo sysfs-content-visible:$path; result=1; fi; done
count=0
for pid in /proc/[0-9]*; do count=$((count + 1)); done
echo process-view-baseline:$count
if [ "$result" -eq 0 ]; then echo process-isolation-view-safe; else echo process-isolation-view-violated; fi
exit "$result""#.into(),
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
        .expect("guest process-view request");
    assert!(matches!(process_view_start.message, GuestMessage::Ready));
    let mut process_view_output = Vec::new();
    let process_view_exit = loop {
        match guest
            .receive(Duration::from_secs(10))
            .await
            .expect("process-view event")
            .message
        {
            GuestMessage::Output { record } => process_view_output.extend(record.payload),
            GuestMessage::ExecExit {
                exit_code,
                signal,
                timed_out,
                ..
            } => break (exit_code, signal, timed_out),
            _ => {}
        }
    };
    assert_eq!(
        process_view_exit,
        (Some(0), None, false),
        "process-view probe output: {:?}",
        String::from_utf8_lossy(&process_view_output)
    );
    let process_view_output = String::from_utf8_lossy(&process_view_output);
    assert!(
        process_view_output.contains("process-isolation-view-safe"),
        "the customer command can see protected guest devices or controls: {process_view_output:?}"
    );
    assert!(
        !process_view_output.contains("process-isolation-view-violated"),
        "the customer command can see protected guest devices or controls: {process_view_output:?}"
    );
    let process_baseline = process_view_output
        .lines()
        .find_map(|line| {
            line.strip_prefix("process-view-baseline:")?
                .parse::<usize>()
                .ok()
        })
        .expect("guest process-view baseline");
    let process_limit = ExecId::new("native-process-limit").unwrap();
    let process_limit_start = guest
        .request(
            OperationId::new("native-process-limit-start").unwrap(),
            GuestMessage::ExecStart {
                spec: Box::new(ExecutionSpec {
                    id: process_limit,
                    argv: vec![
                        "/bin/sh".into(),
                        "-c".into(),
                        r#"echo process-limit-probe-start
/bin/sleep 30 & p1=$!
/bin/sleep 30 & p2=$!
/bin/sleep 30 & p3=$!
count=0
for pid in /proc/[0-9]*; do count=$((count + 1)); done
echo process-limit-saturated:$count
/bin/sleep 30 & p4=$!
echo process-limit-violated:$count
kill "$p1" "$p2" "$p3" "$p4" 2>/dev/null
wait 2>/dev/null
exit 1"#
                            .into(),
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
        .expect("guest process-limit request");
    assert!(matches!(process_limit_start.message, GuestMessage::Ready));
    let mut process_limit_output = Vec::new();
    let process_limit_exit = loop {
        match guest
            .receive(Duration::from_secs(10))
            .await
            .expect("process-limit event")
            .message
        {
            GuestMessage::Output { record } => process_limit_output.extend(record.payload),
            GuestMessage::ExecExit {
                exit_code,
                signal,
                timed_out,
                ..
            } => break (exit_code, signal, timed_out),
            _ => {}
        }
    };
    let process_limit_output = String::from_utf8_lossy(&process_limit_output);
    assert_eq!(
        process_limit_exit,
        (Some(2), None, false),
        "the fourth customer child should be refused by pids.max: {process_limit_output:?}"
    );
    assert!(
        process_limit_output.contains("process-limit-probe-start"),
        "the fork-limit probe did not start: {process_limit_output:?}"
    );
    assert!(
        process_limit_output.contains(&format!("process-limit-saturated:{}", process_baseline + 3)),
        "the fork-limit probe did not reach the measured cap: baseline={process_baseline}, output={process_limit_output:?}"
    );
    let lower_process_limit_output = process_limit_output.to_ascii_lowercase();
    assert!(
        lower_process_limit_output.contains("cannot fork")
            || lower_process_limit_output.contains("can't fork")
            || lower_process_limit_output.contains("resource temporarily unavailable"),
        "the shell did not report a fork resource denial: {process_limit_output:?}"
    );
    assert!(
        !process_limit_output.contains("process-limit-violated:"),
        "the guest admitted more than four customer tasks: {process_limit_output:?}"
    );
    let process_cleanup = ExecId::new("native-process-limit-cleanup").unwrap();
    let process_cleanup_start = guest
        .request(
            OperationId::new("native-process-limit-cleanup-start").unwrap(),
            GuestMessage::ExecStart {
                spec: Box::new(ExecutionSpec {
                    id: process_cleanup,
                    argv: vec![
                        "/bin/sh".into(),
                        "-c".into(),
                        r#"count=0
for pid in /proc/[0-9]*; do count=$((count + 1)); done
if [ "$count" -eq __BASELINE__ ]; then echo process-limit-cleanup-safe:$count; exit 0; fi
echo process-limit-cleanup-leaked:$count
exit 1"#
                            .replace("__BASELINE__", &process_baseline.to_string()),
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
        .expect("guest process-limit cleanup request");
    assert!(matches!(process_cleanup_start.message, GuestMessage::Ready));
    let mut process_cleanup_output = Vec::new();
    let process_cleanup_exit = loop {
        match guest
            .receive(Duration::from_secs(10))
            .await
            .expect("process-limit cleanup event")
            .message
        {
            GuestMessage::Output { record } => process_cleanup_output.extend(record.payload),
            GuestMessage::ExecExit {
                exit_code,
                signal,
                timed_out,
                ..
            } => break (exit_code, signal, timed_out),
            _ => {}
        }
    };
    let process_cleanup_output = String::from_utf8_lossy(&process_cleanup_output);
    assert_eq!(
        process_cleanup_exit,
        (Some(0), None, false),
        "the guest did not clean up saturated customer tasks: {process_cleanup_output:?}"
    );
    assert!(
        process_cleanup_output.contains("process-limit-cleanup-safe:"),
        "the guest did not clean up saturated customer tasks: {process_cleanup_output:?}"
    );
}
