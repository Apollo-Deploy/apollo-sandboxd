//! Stable host compatibility pins exclude transient CPU frequency and boot identity.
use crate::error::{Error, Result};
pub(super) fn host_kernel() -> Result<String> {
    let value = std::fs::read_to_string("/proc/sys/kernel/osrelease")?;
    let value = value.trim();
    if value.is_empty() || value.len() > 128 {
        return Err(Error::State);
    }
    Ok(value.to_owned())
}
pub(super) fn cpu_fingerprint() -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut value = String::new();
    std::fs::File::open("/proc/cpuinfo")?
        .take(1 << 20)
        .read_to_string(&mut value)?;
    let mut stable = std::collections::BTreeSet::new();
    for line in value.lines() {
        if let Some((key, val)) = line.split_once(':') {
            if matches!(
                key.trim(),
                "vendor_id"
                    | "cpu family"
                    | "model"
                    | "stepping"
                    | "microcode"
                    | "flags"
                    | "Features"
                    | "CPU implementer"
                    | "CPU architecture"
                    | "CPU variant"
                    | "CPU part"
                    | "CPU revision"
            ) {
                stable.insert(format!("{}:{}", key.trim(), val.trim()));
            }
        }
    }
    if stable.is_empty() {
        return Err(Error::State);
    }
    Ok(hex::encode(Sha256::digest(
        stable.into_iter().collect::<Vec<_>>().join("\n"),
    )))
}
