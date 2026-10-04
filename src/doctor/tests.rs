use super::{
    catalog::local_identity_collision,
    host::{available_memory, cpu_flags, tested_kernel_branch},
};

#[test]
fn unit_checks_observe_section_and_last_directive() {
    use super::host::required_unit_directives;
    let unit = "[Service]\nKillMode=process\nNoNewPrivileges=yes\nLimitCORE=0\n";
    assert!(required_unit_directives(unit));
    assert!(!required_unit_directives(&format!(
        "{unit}KillMode=control-group\n"
    )));
    assert!(!required_unit_directives(
        &unit.replace("[Service]", "[Unit]")
    ));
}

#[test]
fn host_kernel_matrix_uses_complete_branch_numbers() {
    for release in ["5.10.200", "6.1.150-custom", "6.18.25\n"] {
        assert!(tested_kernel_branch(release));
    }
    for release in ["6.12.107", "6.10.1", "6.180.0", "5.100.0", "", "garbage"] {
        assert!(!tested_kernel_branch(release));
    }
}
#[test]
fn cpu_flags_do_not_use_substring_or_model_name_matches() {
    assert_eq!(
        cpu_flags("model name: vmx hypervisor\nflags: vmxx hypervisorr\n"),
        (false, false)
    );
    assert_eq!(cpu_flags("flags: aes vmx hypervisor ept\n"), (true, true));
    assert_eq!(cpu_flags("flags: svm\n"), (true, false));
}
#[test]
fn memory_units_duplicates_and_overflow_are_rejected() {
    assert_eq!(
        available_memory(b"MemAvailable: 65536 kB\n"),
        Some(64 << 20)
    );
    for bytes in [
        b"MemAvailable: 1 MB\n".as_slice(),
        b"MemAvailable: 1 kB extra\n",
        b"MemAvailable: 1 kB\nMemAvailable: 2 kB\n",
        b"MemAvailable: 18446744073709551615 kB\n",
    ] {
        assert_eq!(available_memory(bytes), None);
    }
}
#[test]
fn identity_pool_collisions_check_both_boundaries_and_malformed_data() {
    assert_eq!(
        local_identity_collision(b"root:x:0:0:root:/root:/bin/sh\n", 100000, 100100),
        Some(false)
    );
    for id in [100000, 100100] {
        assert_eq!(
            local_identity_collision(
                format!("service:x:{id}:0:test\n").as_bytes(),
                100000,
                100100
            ),
            Some(true)
        );
    }
    assert_eq!(local_identity_collision(b"invalid\n", 100000, 100100), None);
}
