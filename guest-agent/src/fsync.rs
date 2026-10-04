//! Trusted state-filesystem synchronization and bounded freeze/thaw.
use std::fs::File;

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod linux {
    use super::*;
    use std::os::fd::AsRawFd;
    // Linux UAPI encodes these as unsigned 32-bit requests. Nix casts to
    // libc's request type (signed int on musl, unsigned long on glibc).
    nix::ioctl_write_int_bad!(freeze, 0xC0045877_u32);
    nix::ioctl_write_int_bad!(thaw, 0xC0045878_u32);

    pub fn freeze_state(state: &File) -> Result<(), String> {
        sync_state(state)?;
        // FIFREEZE takes an integer argument, not a userspace pointer. The
        // owned descriptor pins the bootstrap-opened ext4 filesystem.
        unsafe { freeze(state.as_raw_fd(), 0) }
            .map_err(|e| format!("freeze state filesystem: {e}"))?;
        Ok(())
    }

    pub fn thaw_state(state: &File) -> Result<(), String> {
        // FITHAW has the same integer-argument ABI as FIFREEZE.
        unsafe { thaw(state.as_raw_fd(), 0) }.map_err(|e| format!("thaw state filesystem: {e}"))?;
        Ok(())
    }

    pub fn sync_state(state: &File) -> Result<(), String> {
        nix::unistd::syncfs(state).map_err(|e| format!("sync state filesystem: {e}"))
    }
}

#[cfg(not(target_os = "linux"))]
mod linux {
    use super::*;
    pub fn freeze_state(_: &File) -> Result<(), String> {
        Err("filesystem freeze requires Linux".into())
    }
    pub fn thaw_state(_: &File) -> Result<(), String> {
        Err("filesystem thaw requires Linux".into())
    }
    pub fn sync_state(state: &File) -> Result<(), String> {
        state.sync_all().map_err(|e| e.to_string())
    }
}

pub use linux::{freeze_state, sync_state, thaw_state};
