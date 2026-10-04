use apollo_sandboxd::jailer::{CgroupLimits, VmmResourceLimits};
use sandboxd_protocol::Resources;
use std::path::Path;

fn resources() -> Resources {
    Resources {
        vcpus: 2,
        memory_mib: 256,
        state_disk_mib: 512,
        host_memory_max_bytes: 268_435_456,
        cpu_quota_us: 20_000,
        cpu_period_us: 100_000,
        cpu_profile: None,
        cpuset: None,
        state_rate_limiter: None,
    }
}

#[test]
fn cgroup_limits_are_derived_without_unbounded_values() {
    let limits = CgroupLimits::from_resources(&resources()).expect("valid resource limits");
    assert_eq!(limits.memory_max, 268_435_456);
    assert_eq!(limits.cpu_max, "20000 100000");
    assert_eq!(limits.cpuset, None);
}

#[test]
fn requested_cpuset_is_preserved_for_cgroup_enforcement() {
    let mut value = resources();
    value.cpuset = Some("0-1,4".into());
    let limits = CgroupLimits::from_resources(&value).expect("valid resource limits");
    assert_eq!(limits.cpuset.as_deref(), Some("0-1,4"));
}

#[test]
fn zero_limits_are_rejected_before_kernel_effects() {
    let mut value = resources();
    value.host_memory_max_bytes = 0;
    assert!(CgroupLimits::from_resources(&value).is_err());
    value = resources();
    value.cpu_period_us = 0;
    assert!(CgroupLimits::from_resources(&value).is_err());
}

#[test]
fn cgroup_names_cannot_escape_the_configured_parent() {
    let limits = CgroupLimits::from_resources(&resources()).expect("valid resource limits");
    assert!(
        apollo_sandboxd::jailer::CgroupV2::prepare(Path::new("/tmp"), "../foreign", limits)
            .is_err()
    );
}

#[test]
fn ordinary_filesystem_is_never_treated_as_cgroup_v2() {
    let parent = tempfile::tempdir().expect("private fixture");
    let limits = CgroupLimits::from_resources(&resources()).expect("valid resource limits");
    let result =
        apollo_sandboxd::jailer::CgroupV2::prepare(parent.path(), "session-cgroup", limits);
    assert!(result.is_err());
    assert!(!parent.path().join("session-cgroup").exists());
}

#[test]
fn vmm_file_bound_preserves_memory_and_fixed_disk_capacity() {
    let mut value = resources();
    let disk_limited = VmmResourceLimits::from_resources(&value).expect("disk extent");
    assert_eq!(disk_limited.file_size_bytes, 512 * 1_048_576);
    assert_eq!(disk_limited.open_files, 1024);
    value.memory_mib = 1024;
    let memory_limited = VmmResourceLimits::from_resources(&value).expect("guest memfd");
    assert_eq!(memory_limited.file_size_bytes, 1024 * 1_048_576);
    value.state_disk_mib = 0;
    assert!(VmmResourceLimits::from_resources(&value).is_err());
    value.state_disk_mib = 1_048_577;
    assert!(VmmResourceLimits::from_resources(&value).is_err());
    value.state_disk_mib = 512;
    value.memory_mib = 1_048_577;
    assert!(VmmResourceLimits::from_resources(&value).is_err());
}
