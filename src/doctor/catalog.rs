//! Operator catalogs and existing filesystem/cgroup prerequisites.
use super::{Report, host::bounded_read};
use crate::{
    config::Config,
    error::{Error, Result},
    security::path::SecureDir,
};
#[cfg(target_os = "linux")]
use std::io::Read;
use std::path::Path;

pub(super) fn inspect(report: &mut Report, config: &Config) {
    let pools = &config.identities;
    let capacity = [
        u64::from(pools.uid_last).checked_sub(u64::from(pools.uid_first)),
        u64::from(pools.gid_last).checked_sub(u64::from(pools.gid_first)),
        u64::from(pools.cid_last).checked_sub(u64::from(pools.cid_first)),
    ]
    .into_iter()
    .map(|v| v.and_then(|n| n.checked_add(1)).unwrap_or(0))
    .min()
    .unwrap_or(0);
    report.add("identity_pool_capacity", capacity >= u64::from(config.quotas.max_active_sandboxes),
        format!("configured UID/GID/CID capacity {capacity}; durable allocator tracks live and snapshot-held reservations"));
    for (kind, path, first, last) in [
        ("uid", "/etc/passwd", pools.uid_first, pools.uid_last),
        ("gid", "/etc/group", pools.gid_first, pools.gid_last),
    ] {
        let collision = bounded_read(Path::new(path), 1 << 20)
            .ok()
            .and_then(|bytes| local_identity_collision(&bytes, first, last));
        report.add(format!("{kind}_local_account_collision"), collision == Some(false),
            "configured pool must not overlap local accounts; operator also reserves it against external NSS sources");
    }
    if let Some(settings) = &config.snapshots {
        let key = crate::snapshot::LocalKey::open(&settings.key_file);
        report.add(
            "snapshot_key",
            key.is_ok(),
            key.err().map_or_else(
                || "private owned 32-byte local key; key values are never emitted".into(),
                |e| e.to_string(),
            ),
        );
        let memory = crate::snapshot::validate_memory_policy();
        report.add(
            "snapshot_memory_policy",
            memory.is_ok(),
            memory.err().map_or_else(
                || "host swap disabled; plaintext staging stays anonymous in RAM".into(),
                |e| e.to_string(),
            ),
        );
        directory(report, "snapshot_directory", &settings.directory, true, 1);
    }
    let Some(execution) = &config.execution else {
        report.add(
            "execution",
            false,
            "trusted execution catalog not configured",
        );
        return;
    };
    let roots = execution.validate_roots();
    report.add(
        "execution_roots",
        roots.is_ok(),
        roots.err().map_or_else(
            || {
                "root-owned staging/storage roots, dedicated private Firecracker mount, and safe cgroup path"
                    .into()
            },
            |e| e.to_string(),
        ),
    );
    directory(report, "jailer_root", &execution.operator_root, true, 1);
    directory(
        report,
        "writable_drive_directory",
        &execution.drive_directory,
        true,
        u64::from(config.quotas.max_state_disk_mib) * (1 << 20),
    );
    let controllers = cgroup_prerequisites(&execution.cgroup_parent);
    report.add(
        "cgroup_v2_controllers",
        controllers.is_ok(),
        controllers.err().map_or_else(
            || "cgroup v2 with cpu and memory enabled in configured subtree".into(),
            |e| e.to_string(),
        ),
    );
    let formatter = crate::runtime::verify(&execution.formatter, &execution.formatter_sha256, true);
    report.add(
        "state_formatter",
        formatter.is_ok(),
        formatter.err().map_or_else(
            || "formatter digest/ownership/permissions verified".into(),
            |e| e.to_string(),
        ),
    );
    for image in &execution.images {
        let result = crate::runtime::verify(&image.path, &image.digest.as_str()[7..], false);
        report.add(
            format!("base_image:{}", image.digest.as_str()),
            result.is_ok(),
            result.err().map_or_else(
                || "immutable base artifact digest and safe ownership verified".into(),
                |e| e.to_string(),
            ),
        );
    }
    if let Some(artifactd) = &execution.artifactd {
        directory(report, "prepared_images", &artifactd.prepared_root, true, 1);
    }
    if let Some(path) = &execution.network_namespace_root {
        directory(report, "external_network_catalog", path, false, 1);
    }
    report.add("vsock_control_transport", cfg!(target_os = "linux"),
        "Firecracker host Unix/vsock bridge; no host NIC or /dev/vhost-vsock prerequisite; READY handshake requires native qualification");
}

fn directory(report: &mut Report, name: &str, path: &Path, private: bool, required_bytes: u64) {
    let result = (|| -> Result<u64> {
        let directory = SecureDir::open(path)?;
        let stat = rustix::fs::fstat(directory.as_fd())?;
        if private
            && (stat.st_uid != rustix::process::geteuid().as_raw() || stat.st_mode & 0o777 != 0o700)
        {
            return Err(Error::Path);
        }
        let space = rustix::fs::fstatvfs(directory.as_fd())?;
        space
            .f_bavail
            .checked_mul(space.f_frsize)
            .ok_or(Error::State)
    })();
    report.add(name, result.as_ref().is_ok_and(|bytes| *bytes >= required_bytes),
        result.map_or_else(|e| e.to_string(), |bytes| format!("safe directory; available bytes {bytes}; minimum {required_bytes}; no writes performed")));
}

#[cfg(target_os = "linux")]
fn cgroup_prerequisites(path: &Path) -> Result<()> {
    let directory = SecureDir::open(path)?;
    if u64::try_from(rustix::fs::fstatfs(directory.as_fd())?.f_type).ok() != Some(0x63677270) {
        return Err(Error::Config("configured subtree is not cgroup v2"));
    }
    for name in ["cgroup.controllers", "cgroup.subtree_control"] {
        let mut bytes = Vec::new();
        directory
            .open_handle(name)?
            .take(4097)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 4096 {
            return Err(Error::Config("cgroup controller list size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Error::State)?;
        if !["cpu", "memory"]
            .iter()
            .all(|required| text.split_whitespace().any(|value| value == *required))
        {
            return Err(Error::Config(
                "cpu/memory controllers unavailable or not enabled",
            ));
        }
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn cgroup_prerequisites(_path: &Path) -> Result<()> {
    Err(Error::Config("cgroup v2 requires Linux"))
}

pub(super) fn local_identity_collision(bytes: &[u8], first: u32, last: u32) -> Option<bool> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut collision = false;
    for line in text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let id = line.split(':').nth(2)?.parse::<u32>().ok()?;
        collision |= (first..=last).contains(&id);
    }
    Some(collision)
}
