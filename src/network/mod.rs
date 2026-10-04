//! Host-side network attachment validation and typed launch translation.
//! sandboxd consumes pre-created operator network namespaces; it never creates
//! TAP devices, namespaces, routes, or firewall rules.
use crate::security::path::SecureDir;
use guest_protocol::{GuestAddress, GuestNetworkConfig};
use sandboxd_protocol::{NetworkAttachment, NetworkMode};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};
use std::{
    fs,
    net::IpAddr,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub struct PreparedAttachment {
    pub attachment: NetworkAttachment,
    pub namespace_path: PathBuf,
    pub namespace_file: fs::File,
    pub identity: NetworkIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct NetworkIdentity {
    pub device: u64,
    pub inode: u64,
    pub filesystem_type: u64,
}

pub fn verify_identity(file: &fs::File, expected: &NetworkIdentity) -> Result<(), &'static str> {
    let metadata = file
        .metadata()
        .map_err(|_| "network namespace metadata unavailable")?;
    if metadata.dev() != expected.device || metadata.ino() != expected.inode {
        return Err("network namespace identity changed");
    }
    #[cfg(target_os = "linux")]
    let filesystem_type = u64::try_from(
        rustix::fs::fstatfs(file)
            .map_err(|_| "network namespace filesystem unavailable")?
            .f_type,
    )
    .map_err(|_| "network namespace filesystem unavailable")?;
    #[cfg(target_os = "linux")]
    if filesystem_type != expected.filesystem_type {
        return Err("network namespace filesystem changed");
    }
    Ok(())
}

pub fn prepare(
    mode: &NetworkMode,
    namespace_root: &Path,
) -> Result<Option<PreparedAttachment>, &'static str> {
    let NetworkMode::ExternalAttachment(attachment) = mode else {
        return Ok(None);
    };
    guest_config(attachment)?;
    if !namespace_root.is_absolute() {
        return Err("network catalog root is not absolute");
    }
    let root = SecureDir::open(namespace_root)
        .map_err(|_| "network catalog root is not operator-owned")?;
    let handle = root
        .open_handle(&attachment.namespace_handle)
        .map_err(|_| "network namespace handle is not a verified catalog entry")?;
    if !is_namespace_handle(&handle)? {
        return Err("network namespace handle is not a network namespace");
    }
    let path = namespace_root.join(&attachment.namespace_handle);
    let metadata = handle
        .metadata()
        .map_err(|_| "network namespace metadata unavailable")?;
    #[cfg(target_os = "linux")]
    let filesystem_type = u64::try_from(
        rustix::fs::fstatfs(&handle)
            .map_err(|_| "network namespace filesystem unavailable")?
            .f_type,
    )
    .map_err(|_| "network namespace filesystem unavailable")?;
    #[cfg(not(target_os = "linux"))]
    let filesystem_type = 0;
    let identity = NetworkIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        filesystem_type,
    };
    verify_identity(&handle, &identity)?;
    verify_tap_in_namespace(&path, &attachment.tap_name)?;
    Ok(Some(PreparedAttachment {
        attachment: (**attachment).clone(),
        namespace_path: path,
        namespace_file: handle,
        identity,
    }))
}

/// Validate the externally-owned TAP in a separate process which enters only
/// the pinned network namespace. The daemon never calls setns on one of its
/// multithreaded runtime threads and this probe has no mutation privileges.
pub fn verify_tap_in_namespace(namespace_path: &Path, tap_name: &str) -> Result<(), &'static str> {
    if !namespace_path.is_absolute()
        || tap_name.is_empty()
        || tap_name.len() > 15
        || !tap_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err("invalid network probe input");
    }
    #[cfg(target_os = "linux")]
    {
        let executable =
            std::env::current_exe().map_err(|_| "network probe executable unavailable")?;
        let mut child = std::process::Command::new(executable)
            .arg("--network-probe")
            .arg(namespace_path)
            .arg("--network-probe-tap")
            .arg(tap_name)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|_| "network probe failed to start")?;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(status) = child.try_wait().map_err(|_| "network probe wait failed")? {
                return if status.success() {
                    Ok(())
                } else {
                    Err("network TAP is missing or not a TAP interface")
                };
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err("network TAP probe timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("external networking requires Linux")
    }
}

/// Revalidates an externally-owned attachment before daemon-restart adoption.
/// Durable paths and identities are evidence, never authority by themselves:
/// the catalog entry is reopened descriptor-relatively and the TAP is probed
/// in that exact namespace again.
pub fn verify_persisted(
    attachment: &NetworkAttachment,
    expected_namespace: &Path,
    expected_identity: &NetworkIdentity,
    namespace_root: &Path,
) -> Result<(), &'static str> {
    let prepared = prepare(
        &NetworkMode::ExternalAttachment(Box::new(attachment.clone())),
        namespace_root,
    )?
    .ok_or("external network attachment missing")?;
    if prepared.namespace_path != expected_namespace || prepared.identity != *expected_identity {
        return Err("network attachment identity changed during recovery");
    }
    Ok(())
}

/// Entry point used only by the daemon's short-lived probe child.
#[cfg(target_os = "linux")]
pub fn run_network_probe(namespace_path: &Path, tap_name: &str) -> Result<(), &'static str> {
    use std::os::fd::AsFd;
    let namespace = fs::File::open(namespace_path).map_err(|_| "network namespace unavailable")?;
    rustix::thread::move_into_link_name_space(
        namespace.as_fd(),
        Some(rustix::thread::LinkNameSpaceType::Network),
    )
    .map_err(|_| "cannot enter network namespace")?;
    let ifindex = fs::read_to_string(format!("/sys/class/net/{tap_name}/ifindex"))
        .map_err(|_| "network TAP is absent")?
        .trim()
        .parse::<u32>()
        .map_err(|_| "network interface index invalid")?;
    if ifindex == 0 {
        return Err("network interface index invalid");
    }
    let flags = fs::read_to_string(format!("/sys/class/net/{tap_name}/tun_flags"))
        .map_err(|_| "network interface is not tun/tap")?;
    let flags = u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16)
        .map_err(|_| "network tun flags invalid")?;
    if flags & 0x0002 == 0 || flags & 0x0001 != 0 {
        return Err("network interface is not TAP");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn run_network_probe(_namespace_path: &Path, _tap_name: &str) -> Result<(), &'static str> {
    Err("external networking requires Linux")
}

pub fn guest_config(attachment: &NetworkAttachment) -> Result<GuestNetworkConfig, &'static str> {
    let mut addresses = Vec::with_capacity(attachment.addresses.len());
    for value in &attachment.addresses {
        let (ip, prefix) = value
            .split_once('/')
            .ok_or("network address must include prefix")?;
        let parsed = ip
            .parse::<IpAddr>()
            .map_err(|_| "invalid network address")?;
        let prefix = prefix.parse::<u8>().map_err(|_| "invalid network prefix")?;
        if prefix > if parsed.is_ipv4() { 32 } else { 128 } {
            return Err("invalid network prefix");
        }
        addresses.push(GuestAddress {
            address: parsed.to_string(),
            prefix,
        });
    }
    let config = GuestNetworkConfig {
        interface: "eth0".into(),
        mac: attachment.guest_mac.clone(),
        addresses,
        gateways: attachment.gateways.clone(),
        dns_servers: attachment.dns_servers.clone(),
        mtu: attachment.mtu,
    };
    config
        .validate()
        .map_err(|_| "invalid guest network configuration")?;
    Ok(config)
}

fn is_namespace_handle(file: &fs::File) -> Result<bool, &'static str> {
    let metadata = file
        .metadata()
        .map_err(|_| "network namespace handle unavailable")?;
    if metadata.uid() != 0 || metadata.mode() & 0o777 != 0o600 {
        return Ok(false);
    }
    #[cfg(target_os = "linux")]
    {
        let stat =
            rustix::fs::fstatfs(file).map_err(|_| "network namespace filesystem unavailable")?;
        if stat.f_type != 0x6e736673 {
            return Ok(false);
        }
        let fd_path = format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(file));
        let target =
            fs::read_link(fd_path).map_err(|_| "network namespace identity unavailable")?;
        return Ok(target.to_string_lossy().starts_with("net:["));
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn attachment() -> NetworkAttachment {
        NetworkAttachment {
            attachment_id: "net-a".into(),
            namespace_handle: "ns-a".into(),
            tap_name: "tap0".into(),
            guest_mac: "02:00:00:00:00:01".into(),
            addresses: vec!["192.0.2.2/24".into(), "2001:db8::2/64".into()],
            gateways: vec!["192.0.2.1".into(), "2001:db8::1".into()],
            dns_servers: vec!["192.0.2.53".into()],
            mtu: 1500,
            rx: None,
            tx: None,
        }
    }
    #[test]
    fn guest_translation_preserves_v4_and_v6_prefixes() {
        let config = guest_config(&attachment()).unwrap();
        assert_eq!(config.addresses[0].address, "192.0.2.2");
        assert_eq!(config.addresses[1].prefix, 64);
    }
    #[test]
    fn foreign_catalog_entry_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        assert!(
            prepare(
                &NetworkMode::ExternalAttachment(Box::new(attachment())),
                root.path()
            )
            .is_err()
        );
    }
    #[test]
    fn identity_mismatch_is_rejected() {
        let file = std::fs::File::open("/dev/null").unwrap();
        let expected = NetworkIdentity {
            device: 0,
            inode: 0,
            filesystem_type: 0,
        };
        assert!(verify_identity(&file, &expected).is_err());
    }
}
