use crate::{ExecId, MAX_DATA_BYTES};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretValue(pub String);
impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Binary secret material is volatile, zeroized on release, and redacted in diagnostics.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretBytes(#[serde(with = "serde_bytes")] pub Vec<u8>);
impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputPolicy {
    Required,
    BestEffort,
    Disabled,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StdinMode {
    Closed,
    Stream,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalSize {
    pub rows: u16,
    pub columns: u16,
}

/// Ephemeral mounts exist only in the customer's execution namespace.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionMount {
    Volume {
        volume_id: crate::VolumeId,
        target: String,
        readonly: bool,
    },
    Tmpfs {
        target: String,
        size_bytes: u64,
        readonly: bool,
    },
    Secret {
        target: String,
        value: SecretBytes,
        uid: u32,
        gid: u32,
        mode: u32,
    },
}
impl ExecutionMount {
    pub fn validate(&self) -> Result<(), &'static str> {
        let target = match self {
            Self::Volume { target, .. } => target,
            Self::Tmpfs {
                target, size_bytes, ..
            } => {
                if !(1..=1 << 30).contains(size_bytes) {
                    return Err("invalid tmpfs bounds");
                }
                target
            }
            Self::Secret {
                target,
                value,
                uid,
                gid,
                mode,
            } => {
                if value.0.is_empty()
                    || value.0.len() > MAX_DATA_BYTES
                    || *uid == u32::MAX
                    || *gid == u32::MAX
                    || *mode > 0o777
                {
                    return Err("invalid secret mount");
                }
                target
            }
        };
        if target.len() > 4096
            || !target.starts_with('/')
            || target == "/"
            || target
                .split('/')
                .skip(1)
                .any(|part| part.is_empty() || part == "." || part == ".." || part.contains('\0'))
            || ["/proc", "/sys", "/dev"]
                .iter()
                .any(|reserved| target == reserved || target.starts_with(&format!("{reserved}/")))
        {
            return Err("invalid execution mount");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionSpec {
    pub id: ExecId,
    pub argv: Vec<String>,
    /// When true, an empty argv is resolved from the pinned OCI image's
    /// Entrypoint/Cmd. A non-empty argv is always an exact override.
    #[serde(default)]
    pub use_image_defaults: bool,
    pub cwd: String,
    pub uid: u32,
    pub gid: u32,
    #[serde(default)]
    pub supplementary_groups: Vec<u32>,
    #[serde(default)]
    pub readonly_root: bool,
    #[serde(default)]
    pub mounts: Vec<ExecutionMount>,
    /// Maximum customer processes, including the initial command and every descendant.
    /// Two trusted guest isolation processes are accounted separately by the guest cgroup.
    pub max_processes: u32,
    pub environment: BTreeMap<String, String>,
    pub secret_environment: BTreeMap<String, SecretValue>,
    pub pty: Option<TerminalSize>,
    pub stdin: StdinMode,
    pub timeout_ms: u32,
    pub detached: bool,
    pub output_policy: OutputPolicy,
    /// Aggregate stdout and stderr budget enforced before bytes reach sinks.
    pub output_bytes: u64,
}
impl ExecutionSpec {
    pub fn validate(&self) -> Result<(), &'static str> {
        if (self.argv.is_empty() && !self.use_image_defaults)
            || self.argv.len() > 256
            || self.uid == u32::MAX
            || self.gid == u32::MAX
            || self.supplementary_groups.len() > 32
            || self.supplementary_groups.iter().any(|gid| *gid == u32::MAX)
            || self.timeout_ms == 0
            || !(1..=4096).contains(&self.max_processes)
            || self.cwd.is_empty()
            || self.cwd.len() > 4096
            || !self.cwd.starts_with('/')
            || self.cwd.contains('\0')
            || self.environment.len() > 256
            || self.secret_environment.len() > 64
            || self.output_bytes > 1 << 30
            || (matches!(self.output_policy, OutputPolicy::Required) && self.output_bytes == 0)
        {
            return Err("invalid execution specification");
        }
        if self.mounts.len() > 16 {
            return Err("execution mount count limit");
        }
        let mut targets = std::collections::BTreeSet::new();
        let mut mount_bytes = 0u64;
        let mut secret_bytes = 0usize;
        for mount in &self.mounts {
            mount.validate()?;
            let (target, size_bytes) = match mount {
                ExecutionMount::Volume { target, .. } => (target, 0),
                ExecutionMount::Tmpfs {
                    target, size_bytes, ..
                } => (target, *size_bytes),
                ExecutionMount::Secret { target, value, .. } => {
                    secret_bytes = secret_bytes
                        .checked_add(value.0.len())
                        .ok_or("secret mount size overflow")?;
                    (target, value.0.len() as u64)
                }
            };
            if !targets.insert(target) {
                return Err("duplicate execution mount");
            }
            mount_bytes = mount_bytes
                .checked_add(size_bytes)
                .ok_or("execution mount size overflow")?;
        }
        if secret_bytes > MAX_DATA_BYTES {
            return Err("secret mount size limit");
        }
        if mount_bytes > 1 << 30 {
            return Err("execution mount size limit");
        }
        let mut size = 0usize;
        for arg in &self.argv {
            if arg.contains('\0') {
                return Err("NUL in argv");
            }
            size = size.checked_add(arg.len()).ok_or("argv overflow")?;
        }
        if self.argv.first().is_some_and(String::is_empty) || size > MAX_DATA_BYTES {
            return Err("argv limit");
        }
        let mut env_size = 0usize;
        for (key, value) in self.environment.iter().map(|(k, v)| (k, v.as_str())).chain(
            self.secret_environment
                .iter()
                .map(|(k, v)| (k, v.0.as_str())),
        ) {
            if key.is_empty() || key.contains(['=', '\0']) || value.contains('\0') {
                return Err("invalid environment");
            }
            env_size = env_size
                .checked_add(key.len() + value.len())
                .ok_or("environment overflow")?;
        }
        if env_size > MAX_DATA_BYTES {
            return Err("environment limit");
        }
        if let Some(size) = self.pty
            && (size.rows == 0 || size.columns == 0 || size.rows > 4096 || size.columns > 4096)
        {
            return Err("PTY size limit");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Stream {
    Stdout,
    Stderr,
    Terminal,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputRecord {
    pub exec: ExecId,
    pub stream: Stream,
    pub sequence: u64,
    pub timestamp_unix_ms: u64,
    pub flags: u16,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "item", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecOutputItem {
    Record(OutputRecord),
    Gap {
        from_sequence: u64,
        to_sequence: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecOutputPage {
    pub exec: ExecId,
    pub items: Vec<ExecOutputItem>,
    pub high_watermark: u64,
    /// Transport reset boundaries after an output sequence; zero means before first output.
    #[serde(default)]
    pub transport_gaps: Vec<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecSummary {
    pub exec: ExecId,
    pub running: bool,
    pub exit_code: Option<i32>,
    pub signal: Option<u8>,
    pub timed_out: bool,
    pub output_high_watermark: u64,
}
