//! Capability and syscall boundary installed before customer code.
use nix::libc;

#[allow(unsafe_code)]
pub(super) fn install_customer_boundary() -> std::io::Result<()> {
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const CAP_VERSION_3: u32 = 0x20080522;
    const KEEP: u32 =
        (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 18);
    // Drop every bounding capability except the small set needed for normal
    // root filesystem ownership and mode operations.
    let root_uid = unsafe { libc::geteuid() } == 0;
    if root_uid {
        for cap in 0..=40 {
            if KEEP & (1u32 << cap) == 0 {
                // SAFETY: prctl arguments are scalar; dropping an unsupported
                // bounding capability is harmless only for EINVAL.
                let result = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
                if result < 0
                    && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL)
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
        }
    }
    let header = CapHeader {
        version: CAP_VERSION_3,
        pid: 0,
    };
    let kept = if root_uid { KEEP } else { 0 };
    let data = [
        CapData {
            effective: kept,
            permitted: kept,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    // SAFETY: capset receives pointers to correctly sized kernel ABI structs.
    if unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: PR_SET_NO_NEW_PRIVS and seccomp arguments are scalar/pointer ABI.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    install_seccomp()
}

#[allow(unsafe_code)]
fn install_seccomp() -> std::io::Result<()> {
    use libc::{BPF_ABS, BPF_JEQ, BPF_JMP, BPF_JSET, BPF_K, BPF_LD, BPF_RET, BPF_W};
    let mut filter: Vec<libc::sock_filter> = Vec::new();
    let stmt = |code: u32, k: u32| libc::sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |code: u32, k: u32, jt: u8, jf: u8| libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    };
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xc000_00b7;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP));

    filter.push(stmt(BPF_LD | BPF_W | BPF_ABS, 4));
    filter.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH, 1, 0));
    filter.push(stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_KILL_PROCESS));
    filter.push(stmt(BPF_LD | BPF_W | BPF_ABS, 0));
    #[allow(unused_mut)]
    let mut denied = vec![
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_open_tree,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_mount_setattr,
    ];
    #[cfg(target_arch = "x86_64")]
    denied.extend([libc::SYS_kexec_file_load, libc::SYS_iopl, libc::SYS_ioperm]);
    for nr in denied {
        filter.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr as u32, 0, 1));
        filter.push(stmt(
            BPF_RET | BPF_K,
            libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
        ));
    }
    filter.push(jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_clone as u32,
        0,
        4,
    ));
    filter.push(stmt(BPF_LD | BPF_W | BPF_ABS, 16));
    let namespace_flags = (libc::CLONE_NEWNS
        | libc::CLONE_NEWCGROUP
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUSER
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWNET) as u32;
    filter.push(jump(BPF_JMP | BPF_JSET | BPF_K, namespace_flags, 0, 1));
    filter.push(stmt(
        BPF_RET | BPF_K,
        libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
    ));
    filter.push(stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_ALLOW));
    filter.push(jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_clone3 as u32,
        0,
        1,
    ));
    filter.push(stmt(
        BPF_RET | BPF_K,
        libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32,
    ));
    filter.push(stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_ALLOW));
    let mut program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: filter remains alive until seccomp copies the verified BPF
    // program into the kernel.
    if unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0,
            &mut program,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
