mod support;
use sandboxd_protocol::*;
use support::spec;

fn attachment() -> NetworkAttachment {
    NetworkAttachment {
        attachment_id: "external".into(),
        namespace_handle: "operator-network".into(),
        tap_name: "tap0".into(),
        guest_mac: "02:00:00:00:00:01".into(),
        addresses: vec!["192.0.2.2/24".into()],
        gateways: vec!["192.0.2.1".into()],
        dns_servers: vec!["192.0.2.53".into()],
        mtu: 1500,
        rx: None,
        tx: None,
    }
}
#[test]
fn malformed_external_attachments_are_rejected_without_host_path_authority() {
    let mut sandbox = spec();
    sandbox.network = NetworkMode::ExternalAttachment(Box::new(attachment()));
    assert!(sandbox.validate().is_ok());
    for mac in [
        "bad",
        "ff:ff:ff:ff:ff:ff",
        "00:00:00:00:00:00",
        "01:00:00:00:00:01",
    ] {
        let mut n = attachment();
        n.guest_mac = mac.into();
        sandbox.network = NetworkMode::ExternalAttachment(Box::new(n));
        assert!(sandbox.validate().is_err());
    }
    for address in [
        "192.0.2.2",
        "192.0.2.2/33",
        "::/128",
        "fe80::2/129",
        "evil/0",
    ] {
        let mut n = attachment();
        n.addresses = vec![address.into()];
        sandbox.network = NetworkMode::ExternalAttachment(Box::new(n));
        assert!(sandbox.validate().is_err());
    }
    let mut n = attachment();
    n.namespace_handle = "/proc/self/ns/net".into();
    sandbox.network = NetworkMode::ExternalAttachment(Box::new(n));
    assert!(sandbox.validate().is_err());
}
#[test]
fn resource_and_volume_descriptors_have_finite_safe_bounds() {
    for cpuset in ["0-1,1", "1-0", "0-9999", "0,,1", ""] {
        let mut sandbox = spec();
        sandbox.resources.cpuset = Some(cpuset.into());
        assert!(sandbox.validate().is_err());
    }
    let mut sandbox = spec();
    sandbox.resources.cpuset = Some("0-3,7".into());
    assert!(sandbox.validate().is_ok());
    sandbox.resources.state_rate_limiter = Some(RateLimiter {
        bandwidth: Some(TokenBucket {
            size: 0,
            one_time_burst: None,
            refill_time_ms: 1,
        }),
        operations: None,
    });
    assert!(sandbox.validate().is_err());
    for mount in [
        "/",
        "/tmp/../outside",
        "/tmp//data",
        "relative",
        "/tmp/./data",
    ] {
        let mut sandbox = spec();
        sandbox.volumes.push(Volume {
            id: VolumeId::new("volume").expect("id"),
            catalog_key: "trusted".into(),
            read_only: true,
            guest_mount_point: mount.into(),
            filesystem: "ext4".into(),
            rate_limiter: None,
        });
        assert!(sandbox.validate().is_err());
    }
}
