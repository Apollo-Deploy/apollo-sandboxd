//! Per-execution cgroup-v2 process accounting and cleanup.

#[cfg(target_os = "linux")]
use std::fs::{self, File, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::path::PathBuf;

/// Prepare and verify the guest's cgroup-v2 hierarchy before the supervisor is
/// exposed on vsock. The guest init process is moved out of the root cgroup so
/// the pids controller can be enabled without violating the no-internal-process
/// rule.
#[cfg(target_os = "linux")]
pub(crate) fn initialize() -> Result<(), String> {
    let root = PathBuf::from("/sys/fs/cgroup");
    require_cgroup2_mount(&root)?;
    require_control_file(&root, "cgroup.subtree_control")?;
    let apollo = root.join("apollo");
    let supervisor = apollo.join("supervisor");
    let executions = apollo.join("executions");
    require_pids_controller(&root)?;
    fs::create_dir(&apollo).map_err(|e| format!("create guest cgroup: {e}"))?;
    require_control_file(&apollo, "cgroup.subtree_control")?;
    fs::create_dir(&supervisor).map_err(|e| format!("create supervisor cgroup: {e}"))?;
    write_control(
        &supervisor.join("cgroup.procs"),
        &std::process::id().to_string(),
    )?;
    // PID 1 must leave the mount root before enabling a controller there.
    // Controllers flow down one level at a time, so enable pids at the root
    // before asking the apollo subtree to distribute it to executions.
    write_control(&root.join("cgroup.subtree_control"), "+pids")?;
    require_pids_controller(&apollo)?;
    fs::create_dir(&executions).map_err(|e| format!("create executions cgroup: {e}"))?;
    write_control(&apollo.join("cgroup.subtree_control"), "+pids")?;
    require_pids_controller(&executions)?;
    write_control(&executions.join("cgroup.subtree_control"), "+pids")?;

    // Exercise the exact files required by launch and cancellation before
    // advertising a ready guest. No customer command can run if these are not
    // available on this kernel/filesystem.
    let probe = executions.join("probe");
    fs::create_dir(&probe).map_err(|e| format!("create cgroup capability probe: {e}"))?;
    let result: Result<(), String> = (|| {
        write_control(&probe.join("pids.max"), "4")?;
        let mut configured = String::new();
        File::open(probe.join("pids.max"))
            .and_then(|mut f| f.read_to_string(&mut configured))
            .map_err(|e| format!("read guest pids.max: {e}"))?;
        if configured.trim() != "4" {
            return Err("guest kernel did not apply cgroup pids.max".into());
        }
        write_control(&probe.join("cgroup.kill"), "1")?;
        let mut events = String::new();
        File::open(probe.join("cgroup.events"))
            .and_then(|mut f| f.read_to_string(&mut events))
            .map_err(|e| format!("read guest cgroup.events: {e}"))?;
        if !events.lines().any(|line| line == "populated 0") {
            return Err("guest cgroup probe did not become unpopulated".into());
        }
        Ok(())
    })();
    let remove_result =
        fs::remove_dir(&probe).map_err(|e| format!("remove cgroup capability probe: {e}"));
    result?;
    remove_result?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_pids_controller(cgroup: &std::path::Path) -> Result<(), String> {
    let controllers = fs::read_to_string(cgroup.join("cgroup.controllers"))
        .map_err(|e| format!("read guest cgroup controllers at {}: {e}", cgroup.display()))?;
    if controllers
        .split_ascii_whitespace()
        .any(|controller| controller == "pids")
    {
        Ok(())
    } else {
        Err(format!(
            "guest cgroup at {} does not expose the pids controller",
            cgroup.display()
        ))
    }
}

#[cfg(target_os = "linux")]
fn require_control_file(cgroup: &std::path::Path, name: &str) -> Result<(), String> {
    let path = cgroup.join(name);
    match fs::metadata(&path) {
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(format!(
            "guest cgroup control is not a file: {}",
            path.display()
        )),
        Err(error) => Err(format!(
            "guest cgroup control is missing at {}: {error}",
            path.display()
        )),
    }
}

#[cfg(target_os = "linux")]
fn require_cgroup2_mount(root: &std::path::Path) -> Result<(), String> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| format!("read guest mount table: {error}"))?;
    let expected = root.to_str().ok_or("invalid guest cgroup mount path")?;
    let mounted = mountinfo.lines().any(|line| {
        let Some((mount, filesystem)) = line.split_once(" - ") else {
            return false;
        };
        let mount_fields = mount.split_ascii_whitespace().collect::<Vec<_>>();
        let filesystem_fields = filesystem.split_ascii_whitespace().collect::<Vec<_>>();
        mount_fields.get(4) == Some(&expected) && filesystem_fields.first() == Some(&"cgroup2")
    });
    if mounted {
        Ok(())
    } else {
        Err(format!(
            "guest cgroup path {} is not a cgroup2 mount",
            root.display()
        ))
    }
}

#[cfg(target_os = "linux")]
fn write_control(path: &std::path::Path, value: &str) -> Result<(), String> {
    OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|mut f| f.write_all(value.as_bytes()))
        .map_err(|e| format!("write cgroup control {}: {e}", path.display()))
}
