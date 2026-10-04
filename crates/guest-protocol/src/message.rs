use crate::{
    DirectoryEntry, ExecutionSpec, FileMetadata, FileRequest, GuestHealth, GuestMetrics,
    GuestProcess, OutputRecord, SessionIdentity, TerminalSize,
};
use sandboxd_protocol::{ExecId, OperationId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestEnvelope {
    pub identity: SessionIdentity,
    pub operation: OperationId,
    pub message: GuestMessage,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "message",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum GuestMessage {
    Hello,
    Ready,
    SessionRebind {
        identity: SessionIdentity,
    },
    SessionRebindReady,
    ExecStart {
        spec: Box<ExecutionSpec>,
    },
    ExecStdin {
        exec: ExecId,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        eof: bool,
    },
    ExecResizePty {
        exec: ExecId,
        size: TerminalSize,
    },
    ExecSignal {
        exec: ExecId,
        signal: u8,
    },
    ExecCancel {
        exec: ExecId,
    },
    ExecWait {
        exec: ExecId,
    },
    Output {
        record: OutputRecord,
    },
    OutputGap {
        exec: ExecId,
        from_sequence: u64,
    },
    ExecExit {
        exec: ExecId,
        exit_code: Option<i32>,
        signal: Option<u8>,
        timed_out: bool,
    },
    File {
        request: FileRequest,
    },
    FileResult {
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        offset: u64,
        eof: bool,
        #[serde(default)]
        metadata: Option<FileMetadata>,
        #[serde(default)]
        entries: Vec<DirectoryEntry>,
        #[serde(default)]
        link_target: Option<String>,
    },
    FilesystemSync,
    FilesystemQuiesce,
    FilesystemUnquiesce,
    /// Applies the operator-authorized guest network configuration.  The
    /// host TAP/netns is attached by Firecracker; this message only configures
    /// the guest interface after the authenticated boot handshake.
    ConfigureNetwork {
        config: GuestNetworkConfig,
    },
    /// Mounts catalog-backed virtio block devices after the host handshake.
    ConfigureVolumes {
        volumes: Vec<GuestVolumeConfig>,
    },
    Metrics,
    MetricsResult {
        metrics: GuestMetrics,
    },
    ProcessList,
    ProcessListResult {
        processes: Vec<GuestProcess>,
    },
    Health,
    HealthResult {
        health: GuestHealth,
    },
    Shutdown,
    Ping,
    /// Explicitly releases a completed operation receipt. The caller must
    /// retain the operation ID until it has durably recorded the result.
    RetireOperation {
        operation: OperationId,
    },
    /// Releases terminal metadata after the host has durably recorded it.
    RetireExec {
        exec: ExecId,
    },
    Error {
        code: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GuestNetworkConfig {
    pub interface: String,
    pub mac: String,
    pub addresses: Vec<GuestAddress>,
    pub gateways: Vec<String>,
    pub dns_servers: Vec<String>,
    pub mtu: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GuestAddress {
    pub address: String,
    pub prefix: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GuestVolumeConfig {
    /// Zero is `/dev/vdc`; state occupies `/dev/vdb`.
    pub device_index: u8,
    pub mount_point: String,
    pub filesystem: String,
    pub read_only: bool,
}
impl GuestEnvelope {
    pub fn validate(&self, expected: &SessionIdentity) -> Result<(), &'static str> {
        expected.authenticate(&self.identity)?;
        match &self.message {
            GuestMessage::SessionRebind { identity } => expected.validate_rebind(identity),
            GuestMessage::ExecStart { spec } => spec.validate(),
            GuestMessage::ExecStdin { data, .. } | GuestMessage::FileResult { data, .. }
                if data.len() > sandboxd_protocol::MAX_DATA_BYTES =>
            {
                Err("guest data limit")
            }
            GuestMessage::Output { record }
                if record.payload.len() > sandboxd_protocol::MAX_DATA_BYTES
                    || record.sequence == 0
                    || record.flags != 0 =>
            {
                Err("output record limit")
            }
            GuestMessage::OutputGap { from_sequence, .. } if *from_sequence == 0 => {
                Err("output gap limit")
            }
            GuestMessage::FileResult {
                data,
                entries,
                link_target,
                ..
            } if data.len() > sandboxd_protocol::MAX_DATA_BYTES
                || entries.len() > 256
                || entries
                    .iter()
                    .any(|entry| entry.name.is_empty() || entry.name.len() > 4096)
                || link_target.as_ref().is_some_and(|value| value.len() > 4096) =>
            {
                Err("file result limit")
            }
            GuestMessage::ExecResizePty { size, .. }
                if size.rows == 0
                    || size.columns == 0
                    || size.rows > 4096
                    || size.columns > 4096 =>
            {
                Err("PTY limit")
            }
            GuestMessage::ExecSignal { signal, .. } if *signal == 0 || *signal > 64 => {
                Err("signal limit")
            }
            GuestMessage::File { request } => request.validate(),
            GuestMessage::ConfigureNetwork { config } => config.validate(),
            GuestMessage::ConfigureVolumes { volumes } => validate_volumes(volumes),
            GuestMessage::Error { code } if code.len() > 128 => Err("error limit"),
            _ => Ok(()),
        }
    }
}

fn validate_volumes(volumes: &[GuestVolumeConfig]) -> Result<(), &'static str> {
    let mut mount_points = std::collections::BTreeSet::new();
    if volumes.len() > 16 {
        return Err("guest volume count limit");
    }
    for (index, volume) in volumes.iter().enumerate() {
        let path = volume.mount_point.as_str();
        if usize::from(volume.device_index) != index
            || !mount_points.insert(path)
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
            return Err("guest volume bounds");
        }
    }
    Ok(())
}

impl GuestNetworkConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.interface.is_empty()
            || self.interface.len() > 15
            || !self
                .interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            || self.addresses.len() > 16
            || self.gateways.len() > 4
            || self.dns_servers.len() > 8
            || !(576..=9000).contains(&self.mtu)
            || self.mac.split(':').count() != 6
            || self
                .mac
                .split(':')
                .any(|part| part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err("guest network bounds");
        }
        for address in &self.addresses {
            let ip = address
                .address
                .parse::<std::net::IpAddr>()
                .map_err(|_| "guest address")?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            if address.prefix > max {
                return Err("guest address prefix");
            }
        }
        for value in self.gateways.iter().chain(self.dns_servers.iter()) {
            value
                .parse::<std::net::IpAddr>()
                .map_err(|_| "guest network address")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod volume_tests {
    use super::*;

    fn volume(device_index: u8, mount_point: &str) -> GuestVolumeConfig {
        GuestVolumeConfig {
            device_index,
            mount_point: mount_point.into(),
            filesystem: "ext4".into(),
            read_only: true,
        }
    }

    #[test]
    fn volume_configuration_requires_ordered_devices_and_normalized_mounts() {
        assert!(validate_volumes(&[volume(0, "/data")]).is_ok());
        assert!(validate_volumes(&[volume(1, "/data")]).is_err());
        assert!(validate_volumes(&[volume(0, "/data/../root")]).is_err());
        assert!(validate_volumes(&[volume(0, "/data"), volume(1, "/data")]).is_err());
    }
}
