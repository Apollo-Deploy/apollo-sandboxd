//! Kernel-enforced VMM file and descriptor ceilings, including diagnostics.
use crate::error::{Error, Result};
use sandboxd_protocol::Resources;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmmResourceLimits {
    pub file_size_bytes: u64,
    pub open_files: u32,
}

impl VmmResourceLimits {
    pub fn from_resources(resources: &Resources) -> Result<Self> {
        // RLIMIT_FSIZE also applies to Firecracker's guest-memory memfd and
        // block backing files. A smaller diagnostic-only limit would break
        // valid guest allocation or writes within the fixed state drive.
        if !(64..=1_048_576).contains(&resources.memory_mib)
            || !(1..=1_048_576).contains(&resources.state_disk_mib)
        {
            return Err(Error::Config("invalid VMM file-size resource bound"));
        }
        Ok(Self {
            file_size_bytes: u64::from(resources.memory_mib.max(resources.state_disk_mib))
                .checked_mul(1_048_576)
                .ok_or(Error::Config("VMM file-size resource overflow"))?,
            open_files: 1024,
        })
    }
}
