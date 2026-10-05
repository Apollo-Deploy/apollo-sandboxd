use apollo_sandboxd::{
    api,
    config::Config,
    doctor,
    error::{Error, Result},
    runtime,
    state::Store,
};
use clap::Parser;
use sandboxd_protocol::SessionId;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version,
    about = "Standalone Firecracker control plane (production qualification incomplete)"
)]
struct Args {
    #[arg(long, default_value = "/etc/apollo-sandboxd/config.toml")]
    config: PathBuf,
    #[arg(long)]
    check_config: bool,
    /// Reconcile and stop only sessions owned by the configured durable store.
    #[arg(long, hide = true)]
    cleanup_owned_sessions: bool,
    #[arg(long, hide = true, requires = "cleanup_owned_sessions")]
    cleanup_session: Option<SessionId>,
    #[arg(long, hide = true)]
    network_probe: Option<PathBuf>,
    #[arg(long, hide = true)]
    network_probe_tap: Option<String>,
    #[arg(long, hide = true)]
    internal_recover_mount_placeholders: Option<String>,
}
fn main() -> std::process::ExitCode {
    let result = run();
    if let Err(error) = result {
        eprintln!("{error}");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}
fn run() -> Result<()> {
    let args = Args::parse();
    if let Some(namespace) = args.network_probe {
        let tap = args
            .network_probe_tap
            .ok_or(Error::Config("network probe TAP missing"))?;
        return apollo_sandboxd::network::run_network_probe(&namespace, &tap)
            .map_err(Error::Config);
    }
    if let Some(namespace) = args.internal_recover_mount_placeholders {
        return apollo_sandboxd::session::run_mount_recovery_helper(&namespace);
    }
    let config = if args.cleanup_owned_sessions {
        Config::load_for_cleanup(&args.config)?
    } else {
        Config::load(&args.config)?
    };
    if args.check_config {
        println!("structural configuration valid; artifacts and execution not qualified");
        return Ok(());
    }
    if !cfg!(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )) {
        return Err(Error::Config(
            "unsupported host: native Linux x86_64 or aarch64 execution required",
        ));
    }
    if !args.cleanup_owned_sessions && !doctor::kvm_available() {
        return Err(Error::Config("KVM unavailable; no execution fallback"));
    }
    config
        .security
        .validate_daemon_identity(rustix::process::geteuid().as_raw())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let catalogs = if args.cleanup_owned_sessions {
            runtime::VerifiedCatalogs::load_for_cleanup(&config).await?
        } else {
            runtime::VerifiedCatalogs::load(&config).await?
        };
        let store = Store::open(
            &config.state.directory,
            config.quotas.clone(),
            config.leases.clone(),
            config.state.event_retention,
        )?;
        if args.cleanup_owned_sessions {
            api::cleanup_owned_sessions(config, store, catalogs, args.cleanup_session).await
        } else {
            api::serve_with_runtime(config, store, catalogs).await
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_session_requires_cleanup_mode() {
        assert!(Args::try_parse_from(["apollo-sandboxd", "--cleanup-session", "target"]).is_err());
        let args = Args::try_parse_from([
            "apollo-sandboxd",
            "--cleanup-owned-sessions",
            "--cleanup-session",
            "target",
        ])
        .expect("exact cleanup is accepted with cleanup mode");
        assert_eq!(args.cleanup_session.expect("session id").as_str(), "target");
    }
}
