//! Anonymous snapshot staging must not become plaintext swap storage.
#[cfg(target_os = "linux")]
use crate::error::Error;
use crate::error::Result;

pub fn validate_memory_policy() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::io::Read;
        let fd = rustix::fs::open(
            "/proc/swaps",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        let mut bytes = Vec::new();
        std::fs::File::from(fd)
            .take(65537)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 65536 || !swap_disabled(&bytes) {
            return Err(Error::Config(
                "encrypted snapshots require disabled host swap",
            ));
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(sandboxd_protocol::ApiError::new(
            sandboxd_protocol::ErrorCode::UnsupportedHost,
            "snapshot memory staging requires Linux",
        )
        .into())
    }
}

fn swap_disabled(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut lines = text.lines();
    lines.next().is_some_and(|header| {
        header
            .split_whitespace()
            .eq(["Filename", "Type", "Size", "Used", "Priority"])
    }) && lines.all(|line| line.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::swap_disabled;

    #[test]
    fn missing_malformed_and_enabled_swap_fail_closed() {
        let header = b"Filename\tType\tSize\tUsed\tPriority\n";
        assert!(swap_disabled(header));
        assert!(!swap_disabled(b""));
        assert!(!swap_disabled(b"Filename Type Size Used\n"));
        assert!(!swap_disabled(
            b"Filename Type Size Used Priority\n/swap file 1024 0 -2\n"
        ));
        assert!(!swap_disabled(b"Filename Type Size Used Priority\n\xff"));
    }
}
