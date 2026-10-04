use crate::{config::Config, runtime, security::path::SecureDir};
use serde::Serialize;
use std::path::Path;
mod catalog;
mod host;
#[cfg(test)]
mod tests;

#[derive(Debug, Serialize)]
pub struct Check {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub passed: bool,
    pub qualification: &'static str,
    pub checks: Vec<Check>,
}
impl Report {
    fn add(&mut self, name: impl Into<String>, passed: bool, detail: impl Into<String>) {
        self.checks.push(Check {
            name: name.into(),
            passed,
            detail: detail.into(),
        });
        self.passed &= passed;
    }
}
pub fn kvm_available() -> bool {
    host::kvm_api_version().is_ok_and(|version| version == 12)
}
pub async fn inspect(config: Option<&Config>) -> Report {
    let mut report = Report {
        passed: true,
        qualification: "APOLLO_SANDBOXD_PRODUCTION_PARTIAL",
        checks: Vec::new(),
    };
    report.add("linux", cfg!(target_os = "linux"), std::env::consts::OS);
    report.add(
        "architecture",
        matches!(std::env::consts::ARCH, "x86_64" | "aarch64"),
        std::env::consts::ARCH,
    );
    let kvm = host::kvm_api_version();
    report.add(
        "kvm_api",
        kvm.as_ref().is_ok_and(|version| *version == 12),
        kvm.map_or_else(
            |e| e.to_string(),
            |version| format!("KVM API {version}; no VM created"),
        ),
    );
    host::inspect(&mut report);
    if let Some(config) = config {
        let socket = crate::api::socket_preflight(&config.daemon);
        report.add(
            "socket_filesystem",
            socket.is_ok(),
            socket.err().map_or_else(
                || "read-only xattr/mount probe; actual ownership writes and directory fsync must succeed before publication".into(),
                |error| error.to_string(),
            ),
        );
        let clients = config
            .security
            .validate_daemon_identity(rustix::process::geteuid().as_raw());
        report.add("daemon_client_identity", clients.is_ok(),
            "host root is trusted; a non-root daemon requires a distinct explicit client UID allowlist");
        report.add(
            "configuration",
            config.validate().is_ok(),
            "bounded schema and catalogs",
        );
        for profile in &config.runtimes {
            let result = runtime::verify_runtime(profile).await;
            report.add(
                format!("runtime:{}", profile.name),
                result.is_ok(),
                result.err().map_or_else(
                    || "digest/ownership/permissions/ELF/version verified".into(),
                    |e| e.to_string(),
                ),
            );
        }
        for profile in &config.kernels {
            for (name, path, digest) in [
                ("kernel", &profile.kernel, &profile.kernel_sha256),
                ("initramfs", &profile.initramfs, &profile.initramfs_sha256),
            ] {
                let result = runtime::verify(path, digest, false);
                report.add(
                    format!("{name}:{}", profile.name),
                    result.is_ok(),
                    result.err().map_or_else(
                        || "artifact digest/ownership/permissions verified".into(),
                        |e| e.to_string(),
                    ),
                );
            }
        }
        for (name, path) in [
            ("state_directory", config.state.directory.as_path()),
            (
                "socket_parent",
                config.daemon.socket.parent().unwrap_or(Path::new("/")),
            ),
        ] {
            let result = SecureDir::open(path);
            report.add(
                name,
                result.is_ok(),
                "directory chain ownership and no symlink traversal",
            );
        }
        catalog::inspect(&mut report, config);
    } else {
        report.add(
            "configuration",
            false,
            "configuration not supplied or could not be safely loaded",
        );
    }
    // Read-only doctor checks never imply a native release qualification.
    report
}
