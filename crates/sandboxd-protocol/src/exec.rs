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
    pub environment: BTreeMap<String, String>,
    pub secret_environment: BTreeMap<String, SecretValue>,
    pub pty: Option<TerminalSize>,
    pub stdin: StdinMode,
    pub timeout_ms: u32,
    pub detached: bool,
    pub output_policy: OutputPolicy,
}
impl ExecutionSpec {
    pub fn validate(&self) -> Result<(), &'static str> {
        if (self.argv.is_empty() && !self.use_image_defaults)
            || self.argv.len() > 256
            || self.timeout_ms == 0
            || self.cwd.is_empty()
            || self.cwd.len() > 4096
            || !self.cwd.starts_with('/')
            || self.cwd.contains('\0')
            || self.environment.len() > 256
            || self.secret_environment.len() > 64
        {
            return Err("invalid execution specification");
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
