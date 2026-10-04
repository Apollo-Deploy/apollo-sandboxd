use crate::{ApiError, ErrorCode, NetworkAttachment, RateLimiter, SandboxId, Volume};
use std::{collections::BTreeSet, net::IpAddr};

pub fn rate(limiter: &Option<RateLimiter>) -> bool {
    limiter.as_ref().is_none_or(|limiter| {
        (limiter.bandwidth.is_some() || limiter.operations.is_some())
            && [&limiter.bandwidth, &limiter.operations]
                .into_iter()
                .all(|bucket| {
                    bucket.as_ref().is_none_or(|bucket| {
                        bucket.size > 0
                            && bucket.size <= i64::MAX as u64
                            && (1..=86_400_000).contains(&bucket.refill_time_ms)
                            && bucket
                                .one_time_burst
                                .is_none_or(|burst| burst <= i64::MAX as u64)
                    })
                })
    })
}

pub fn cpuset(value: &Option<String>) -> bool {
    let Some(value) = value else {
        return true;
    };
    if value.is_empty() || value.len() > 256 {
        return false;
    }
    let mut previous = None;
    for part in value.split(',') {
        let mut range = part.split('-');
        let Some(start) = range.next().and_then(|v| v.parse::<u16>().ok()) else {
            return false;
        };
        let end = match range.next() {
            Some(v) => match v.parse::<u16>() {
                Ok(v) => v,
                Err(_) => return false,
            },
            None => start,
        };
        if range.next().is_some()
            || end < start
            || end > 8191
            || previous.is_some_and(|p| start <= p)
        {
            return false;
        }
        previous = Some(end);
    }
    true
}

pub fn network(n: &NetworkAttachment) -> Result<(), ApiError> {
    let invalid = || {
        ApiError::new(
            ErrorCode::NetworkAttachmentInvalid,
            "invalid network descriptor",
        )
    };
    if SandboxId::new(&n.attachment_id).is_err()
        || SandboxId::new(&n.namespace_handle).is_err()
        || n.tap_name.is_empty()
        || n.tap_name.len() > 15
        || n.tap_name == "."
        || n.tap_name == ".."
        || !n
            .tap_name
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b"_.-".contains(&v))
        || !(576..=9000).contains(&n.mtu)
        || n.addresses.len() > 16
        || n.gateways.len() > 4
        || n.dns_servers.len() > 8
        || !rate(&n.rx)
        || !rate(&n.tx)
    {
        return Err(invalid());
    }
    let parts: Vec<_> = n.guest_mac.split(':').collect();
    if parts.len() != 6
        || parts
            .iter()
            .any(|part| part.len() != 2 || !part.bytes().all(|v| v.is_ascii_hexdigit()))
    {
        return Err(invalid());
    }
    let octets: Vec<_> = parts
        .iter()
        .map(|part| u8::from_str_radix(part, 16))
        .collect::<Result<_, _>>()
        .map_err(|_| invalid())?;
    if octets[0] & 1 != 0 || octets.iter().all(|v| *v == 0) {
        return Err(invalid());
    }
    let mut addresses = BTreeSet::new();
    for address in &n.addresses {
        let Some((ip, prefix)) = address.split_once('/') else {
            return Err(invalid());
        };
        let ip = ip.parse::<IpAddr>().map_err(|_| invalid())?;
        let prefix = prefix.parse::<u8>().map_err(|_| invalid())?;
        if ip.is_unspecified()
            || ip.is_multicast()
            || prefix > if ip.is_ipv4() { 32 } else { 128 }
            || (ip.is_ipv6() && n.mtu < 1280)
            || !addresses.insert((ip, prefix))
        {
            return Err(invalid());
        }
    }
    for list in [&n.gateways, &n.dns_servers] {
        let mut unique = BTreeSet::new();
        for value in list {
            let ip = value.parse::<IpAddr>().map_err(|_| invalid())?;
            if ip.is_unspecified() || ip.is_multicast() || !unique.insert(ip) {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

pub fn volumes(volumes: &[Volume]) -> Result<(), ApiError> {
    let invalid = || ApiError::new(ErrorCode::VolumeInvalid, "invalid volume descriptor");
    let mut ids = BTreeSet::new();
    let mut mounts = BTreeSet::new();
    for volume in volumes {
        let path = &volume.guest_mount_point;
        if !ids.insert(volume.id.as_str())
            || !mounts.insert(path)
            || SandboxId::new(&volume.catalog_key).is_err()
            || !rate(&volume.rate_limiter)
            || path.len() > 4096
            || !path.starts_with('/')
            || path == "/"
            || path.contains('\0')
            || path
                .split('/')
                .skip(1)
                .any(|part| part.is_empty() || part == "." || part == "..")
            || !matches!(
                volume.filesystem.as_str(),
                "ext4" | "xfs" | "btrfs" | "vfat"
            )
        {
            return Err(invalid());
        }
    }
    Ok(())
}
