use apollo_sandboxd::process::ProcessIdentity;

#[cfg(target_os = "linux")]
#[test]
fn owned_child_identity_is_revalidated_and_signaled_by_pidfd() {
    let child = std::process::Command::new("/usr/bin/sleep")
        .arg("30")
        .spawn()
        .expect("owned fixture child starts");
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = ChildGuard(child);
    let identity = ProcessIdentity::capture(child.0.id()).expect("pidfd identity captures");
    identity.verify().expect("captured identity remains valid");
    assert_eq!(identity.pid(), child.0.id());
    assert!(identity.start_time_ticks() > 0);
    assert!(!identity.executable_sha256().is_empty());
    assert!(!identity.cgroup_sha256().is_empty());
    identity
        .send_signal(rustix::process::Signal::TERM)
        .expect("signal targets the captured pidfd");
    let status = child.0.wait().expect("owned fixture child reaps");
    assert!(!status.success());
}

#[cfg(target_os = "linux")]
#[test]
fn persisted_identity_rejects_mismatch_and_dead_process() {
    let mut child = std::process::Command::new("/usr/bin/sleep")
        .arg("30")
        .spawn()
        .expect("owned fixture child starts");
    let identity = ProcessIdentity::capture(child.id()).expect("identity captures");
    let mut record = identity.persisted();
    record.start_time_ticks = record.start_time_ticks.saturating_add(1);
    assert!(ProcessIdentity::reopen_verified(&record).is_err());
    child.kill().expect("owned fixture stops");
    child.wait().expect("owned fixture reaps");
    assert!(ProcessIdentity::reopen_verified(&identity.persisted()).is_err());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn process_identity_fails_closed_off_linux() {
    let error = ProcessIdentity::capture(1).expect_err("pid identity is Linux-only");
    assert!(error.to_string().contains("requires Linux"));
}
