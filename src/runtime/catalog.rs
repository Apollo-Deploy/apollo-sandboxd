use crate::{
    config::RuntimeProfile,
    error::{Error, Result},
    runtime::{VerifiedArtifact, verify},
};
use sandboxd_protocol::Architecture;
#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(target_os = "linux")]
use std::{process::Stdio, time::Duration};
#[cfg(target_os = "linux")]
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

/// A verified, retained runtime pair. The open descriptors pin the exact
/// inodes that were checked; callers must retain this value for the session.
pub struct VerifiedRuntime {
    pub profile_name: String,
    pub version: String,
    pub architecture: Architecture,
    pub firecracker: VerifiedArtifact,
    pub jailer: VerifiedArtifact,
}

impl VerifiedRuntime {
    /// Clone the retained descriptors for one launch without reopening any
    /// mutable catalog pathname.
    pub fn duplicate(&self) -> Result<Self> {
        Ok(Self {
            profile_name: self.profile_name.clone(),
            version: self.version.clone(),
            architecture: self.architecture,
            firecracker: self.firecracker.duplicate()?,
            jailer: self.jailer.duplicate()?,
        })
    }
}

pub async fn verify_runtime(profile: &RuntimeProfile) -> Result<VerifiedRuntime> {
    let mut firecracker = verify(&profile.firecracker, &profile.firecracker_sha256, true)?;
    let mut jailer = verify(&profile.jailer, &profile.jailer_sha256, true)?;
    verify_elf(&mut firecracker, profile.architecture)?;
    verify_elf(&mut jailer, profile.architecture)?;
    #[cfg(target_os = "linux")]
    {
        let native = match std::env::consts::ARCH {
            "x86_64" => Architecture::X86_64,
            "aarch64" => Architecture::Aarch64,
            _ => return Err(Error::Artifact("unsupported host architecture")),
        };
        if profile.architecture != native {
            return Err(Error::Artifact("runtime architecture does not match host"));
        }
        version(&firecracker, &format!("Firecracker v{}", profile.version)).await?;
        version(&jailer, &format!("Jailer v{}", profile.version)).await?;
        firecracker.revalidate()?;
        jailer.revalidate()?;
        Ok(VerifiedRuntime {
            profile_name: profile.name.clone(),
            version: profile.version.clone(),
            architecture: profile.architecture,
            firecracker,
            jailer,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Error::Artifact(
            "runtime execution verification requires Linux",
        ))
    }
}
fn verify_elf(artifact: &mut VerifiedArtifact, architecture: Architecture) -> Result<()> {
    let mut header = [0; 20];
    let mut offset = 0;
    while offset < header.len() {
        let count = artifact
            .file
            .read_at(&mut header[offset..], offset as u64)?;
        if count == 0 {
            return Err(Error::Artifact("runtime ELF header truncated"));
        }
        offset += count;
    }
    let machine = u16::from_le_bytes([header[18], header[19]]);
    let expected = match architecture {
        Architecture::X86_64 => 62,
        Architecture::Aarch64 => 183,
    };
    if &header[..4] != b"\x7fELF" || header[4] != 2 || header[5] != 1 || machine != expected {
        return Err(Error::Artifact("runtime ELF architecture mismatch"));
    }
    Ok(())
}
#[cfg(target_os = "linux")]
async fn version(artifact: &VerifiedArtifact, expected: &str) -> Result<()> {
    // execve resolves the still-open verified FD before CLOEXEC closes it. Only ELF is allowed.
    let executable = artifact.proc_fd_path();
    let mut child = Command::new(executable)
        .arg("--version")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or(Error::Artifact("missing runtime version output"))?;
    let result = timeout(Duration::from_secs(5), async {
        let mut bytes = Vec::new();
        stdout.take(8193).read_to_end(&mut bytes).await?;
        let status = child.wait().await?;
        if !status.success() || !matches_version(&bytes, expected) {
            return Err(Error::Artifact("runtime version mismatch"));
        }
        Ok(())
    })
    .await;
    result.map_err(|_| Error::Artifact("runtime version timeout"))?
}

#[cfg(any(target_os = "linux", test))]
fn matches_version(bytes: &[u8], expected: &str) -> bool {
    // Verified Firecracker releases print diagnostics after the version line.
    // Accept only the exact first line, rather than a substring in log output.
    bytes.len() <= 8192
        && std::str::from_utf8(bytes)
            .ok()
            .and_then(|text| text.lines().next())
            == Some(expected)
}

#[cfg(test)]
mod tests {
    use super::matches_version;

    #[test]
    fn version_allows_bounded_trailing_diagnostics() {
        assert!(matches_version(
            b"Firecracker v1.17.0\n\nlog: exit_code=0\n",
            "Firecracker v1.17.0"
        ));
        assert!(matches_version(b"Jailer v1.17.0\n", "Jailer v1.17.0"));
        for output in [
            b"Firecracker v1.17.1\n".as_slice(),
            b"log: Firecracker v1.17.0\n",
            b"\nFirecracker v1.17.0\n",
            b"Firecracker v1.17.0 suffix\n",
            b"Firecracker v1.17.0\n\xff",
        ] {
            assert!(!matches_version(output, "Firecracker v1.17.0"));
        }
        let mut oversized = b"Firecracker v1.17.0\n".to_vec();
        oversized.resize(8193, b'x');
        assert!(!matches_version(&oversized, "Firecracker v1.17.0"));
    }
}
