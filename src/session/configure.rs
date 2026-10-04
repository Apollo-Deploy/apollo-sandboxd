use crate::error::{Error, Result};
use firecracker_api::{
    BootSource, Client, CpuTemplate, Drive, MachineConfiguration, SerialDevice, Vsock,
};
use sandboxd_protocol::Resources;
use std::path::Path;
pub(super) struct ConfigureInputs<'a> {
    pub resources: &'a Resources,
    pub boot_args: &'a str,
    pub cid: u32,
    pub vsock_socket: &'a Path,
    pub serial_out_path: &'a str,
    pub network: Option<sandboxd_protocol::NetworkAttachment>,
    pub volumes: &'a [sandboxd_protocol::Volume],
}

pub(super) async fn configure(client: &Client, input: &ConfigureInputs<'_>) -> Result<()> {
    let cpu_template = cpu_template(input.resources.cpu_profile.as_deref())?;
    client
        .machine(&MachineConfiguration {
            vcpu_count: input.resources.vcpus,
            mem_size_mib: input.resources.memory_mib,
            smt: false,
            track_dirty_pages: false,
            cpu_template,
        })
        .await
        .map_err(|_| Error::Config("machine configuration failed"))?;
    client
        .serial(&SerialDevice {
            serial_out_path: input.serial_out_path.to_owned(),
            rate_limiter: None,
        })
        .await
        .map_err(|_| Error::Config("serial configuration failed"))?;
    client
        .boot_source(&BootSource {
            kernel_image_path: "/vmlinux".into(),
            initrd_path: Some("/initramfs".into()),
            boot_args: input.boot_args.to_owned(),
        })
        .await
        .map_err(|_| Error::Config("boot source configuration failed"))?;
    client
        .drive(&Drive {
            drive_id: "base".into(),
            path_on_host: "/base.img".into(),
            is_root_device: true,
            is_read_only: true,
            rate_limiter: None,
        })
        .await
        .map_err(|_| Error::Config("base drive configuration failed"))?;
    client
        .drive(&Drive {
            drive_id: "state".into(),
            path_on_host: "/state.img".into(),
            is_root_device: false,
            is_read_only: false,
            rate_limiter: input
                .resources
                .state_rate_limiter
                .as_ref()
                .map(rate_limiter),
        })
        .await
        .map_err(|_| Error::Config("state drive configuration failed"))?;
    for drive in volume_drives(input.volumes)? {
        client
            .drive(&drive)
            .await
            .map_err(|_| Error::Config("catalog volume drive configuration failed"))?;
    }
    if let Some(network) = &input.network {
        client
            .network(&firecracker_api::NetworkInterface {
                iface_id: network.attachment_id.clone(),
                host_dev_name: network.tap_name.clone(),
                guest_mac: network.guest_mac.clone(),
                rx_rate_limiter: network.rx.as_ref().map(rate_limiter),
                tx_rate_limiter: network.tx.as_ref().map(rate_limiter),
            })
            .await
            .map_err(|_| Error::Config("network interface configuration failed"))?;
    }
    client
        .vsock(&Vsock {
            guest_cid: input.cid,
            uds_path: input.vsock_socket.to_string_lossy().into_owned(),
        })
        .await
        .map_err(|_| Error::Config("vsock configuration failed"))?;
    Ok(())
}

fn cpu_template(value: Option<&str>) -> Result<Option<CpuTemplate>> {
    match value {
        None | Some("none") => Ok(None),
        Some("c3") => Ok(Some(CpuTemplate::C3)),
        Some("t2") => Ok(Some(CpuTemplate::T2)),
        Some("t2s") => Ok(Some(CpuTemplate::T2S)),
        Some("t2cl") => Ok(Some(CpuTemplate::T2CL)),
        Some(_) => Err(Error::Config(
            "CPU profile is not allowed on the x86_64 runtime",
        )),
    }
}

fn rate_limiter(value: &sandboxd_protocol::RateLimiter) -> firecracker_api::RateLimiter {
    fn bucket(value: &sandboxd_protocol::TokenBucket) -> firecracker_api::TokenBucket {
        firecracker_api::TokenBucket {
            size: value.size,
            one_time_burst: value.one_time_burst,
            refill_time: value.refill_time_ms,
        }
    }
    firecracker_api::RateLimiter {
        bandwidth: value.bandwidth.as_ref().map(bucket),
        ops: value.operations.as_ref().map(bucket),
    }
}

fn volume_drives(volumes: &[sandboxd_protocol::Volume]) -> Result<Vec<Drive>> {
    volumes
        .iter()
        .map(|volume| {
            let name = crate::volume_catalog::staged_name(volume.id.as_str())?;
            Ok(Drive {
                drive_id: format!("volume-{}", volume.id.as_str()),
                path_on_host: format!("/{name}"),
                is_root_device: false,
                is_read_only: volume.read_only,
                rate_limiter: volume.rate_limiter.as_ref().map(rate_limiter),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_cpu_profiles_are_explicitly_allowlisted() {
        assert!(matches!(cpu_template(None).unwrap(), None));
        assert!(matches!(
            cpu_template(Some("c3")).unwrap(),
            Some(CpuTemplate::C3)
        ));
        assert!(matches!(
            cpu_template(Some("t2cl")).unwrap(),
            Some(CpuTemplate::T2CL)
        ));
        assert!(cpu_template(Some("t2a")).is_err());
        assert!(cpu_template(Some("arbitrary")).is_err());
    }

    #[test]
    fn catalog_volume_drives_use_deterministic_staged_names_and_policy() {
        let volumes = [sandboxd_protocol::Volume {
            id: sandboxd_protocol::VolumeId::new("reports".to_owned()).unwrap(),
            catalog_key: "reports".into(),
            read_only: true,
            guest_mount_point: "/reports".into(),
            filesystem: "ext4".into(),
            rate_limiter: Some(sandboxd_protocol::RateLimiter {
                bandwidth: Some(sandboxd_protocol::TokenBucket {
                    size: 4096,
                    one_time_burst: Some(512),
                    refill_time_ms: 250,
                }),
                operations: None,
            }),
        }];
        let drives = volume_drives(&volumes).unwrap();
        assert_eq!(drives.len(), 1);
        assert_eq!(drives[0].drive_id, "volume-reports");
        assert_eq!(drives[0].path_on_host, "/volume-reports.img");
        assert!(!drives[0].is_root_device);
        assert!(drives[0].is_read_only);
        let limit = drives[0].rate_limiter.as_ref().unwrap();
        let bandwidth = limit.bandwidth.as_ref().unwrap();
        assert_eq!(bandwidth.size, 4096);
        assert_eq!(bandwidth.one_time_burst, Some(512));
        assert_eq!(bandwidth.refill_time, 250);
        assert!(limit.ops.is_none());
    }
}

/// Firecracker snapshot/load must be the first configuration action on the fresh process.
pub(super) async fn restore(
    client: &Client,
    network: Option<&sandboxd_protocol::NetworkAttachment>,
    vsock: &Path,
) -> Result<()> {
    use firecracker_api::{
        MemoryBackend, MemoryBackendType, NetworkOverride, SnapshotLoad, VsockOverride,
    };
    client
        .snapshot_load(&SnapshotLoad {
            snapshot_path: "/restore-state".into(),
            mem_backend: MemoryBackend {
                backend_type: MemoryBackendType::File,
                backend_path: "/restore-memory".into(),
            },
            enable_diff_snapshots: false,
            resume_vm: true,
            network_overrides: network
                .map(|n| {
                    vec![NetworkOverride {
                        iface_id: n.attachment_id.clone(),
                        host_dev_name: n.tap_name.clone(),
                    }]
                })
                .unwrap_or_default(),
            vsock_override: VsockOverride {
                uds_path: vsock.to_string_lossy().into_owned(),
            },
        })
        .await
        .map_err(|_| Error::Config("authenticated full snapshot load failed"))
}
