use super::configure::{ConfigureInputs, configure};
use super::{AssetIdentity, AssetsManifest, StagedAssets};
use crate::{
    error::{Error, Result},
    jailer::{CgroupV2, JailStage, JailerLaunchSpec, build_jailer_command},
    process::{PersistedProcessIdentity, ProcessIdentity},
    runtime::{VerifiedKernel, VerifiedRuntime},
    state::LaunchIntent,
};
use firecracker_api::Client;
use sandboxd_protocol::{NetworkMode, Resources};
use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{process::Command, time::sleep};

/// The durable store must record this manifest before spawning jailer. It is
/// the recovery proof for a daemon crash before a VMM PID can be recorded.
pub trait LaunchJournal {
    /// Reserves both RLIMIT_FSIZE-bounded diagnostic files before the jailer
    /// command creates `jailer.stderr`.
    fn reserve_diagnostics(&mut self, resources: &Resources) -> Result<()>;
    fn reserve_resources(&mut self, manifest: &LaunchManifest) -> Result<()>;
    fn record_process(&mut self, process: &ProcessIdentity) -> Result<()>;
    fn record_socket_identities(&mut self, api: AssetIdentity, vsock: AssetIdentity) -> Result<()>;
    fn record_jail_tree(&mut self, tree: &super::JailTreeManifest) -> Result<()>;
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchManifest {
    pub sandbox_id: String,
    pub session_id: String,
    pub jail_root: PathBuf,
    pub cgroup: PathBuf,
    pub api_socket: PathBuf,
    pub vsock_socket: PathBuf,
    #[serde(default)]
    pub api_socket_identity: Option<AssetIdentity>,
    #[serde(default)]
    pub vsock_socket_identity: Option<AssetIdentity>,
    pub jail_identity: crate::jailer::JailIdentity,
    #[serde(default)]
    pub staged_jail: Option<crate::jailer::JailStageManifest>,
    pub cgroup_identity: crate::jailer::CgroupIdentity,
    pub assets: AssetsManifest,
    #[serde(default)]
    pub jail_tree: Option<super::JailTreeManifest>,
    #[serde(default)]
    pub network_identity: Option<crate::network::NetworkIdentity>,
    #[serde(default)]
    pub network_attachment: Option<sandboxd_protocol::NetworkAttachment>,
    #[serde(default)]
    pub network_namespace: Option<PathBuf>,
}

pub struct LaunchInputs<'a> {
    pub intent: &'a LaunchIntent,
    pub runtime: &'a mut VerifiedRuntime,
    pub kernel: &'a mut VerifiedKernel,
    pub stage: JailStage,
    pub cgroup: CgroupV2,
    pub assets: &'a StagedAssets,
    pub resources: Resources,
    pub network: NetworkMode,
    pub volumes: Vec<sandboxd_protocol::Volume>,
    pub network_namespace_root: Option<PathBuf>,
    pub api_socket: PathBuf,
    pub vsock_socket: PathBuf,
    pub boot_args: &'a str,
    pub timeout: Duration,
    pub restore: bool,
}

pub struct LaunchResult {
    pub process: ProcessIdentity,
    pub process_record: PersistedProcessIdentity,
    pub manifest: LaunchManifest,
    pub api_socket: PathBuf,
    pub vsock_socket: PathBuf,
}

/// Launches only the verified jailer path. The caller must have committed the
/// matching LaunchIntent before entering this function.
pub async fn launch(
    input: LaunchInputs<'_>,
    journal: &mut dyn LaunchJournal,
) -> Result<LaunchResult> {
    validate_input(&input)?;
    input.runtime.firecracker.revalidate()?;
    input.runtime.jailer.revalidate()?;
    input.kernel.kernel.revalidate()?;
    input.kernel.initramfs.revalidate()?;
    let prepared_network = match &input.network {
        NetworkMode::None => None,
        NetworkMode::ExternalAttachment(_) => crate::network::prepare(
            &input.network,
            input
                .network_namespace_root
                .as_deref()
                .ok_or(Error::Config("network catalog root missing"))?,
        )
        .map_err(Error::Config)?,
    };
    let network_attachment = prepared_network
        .as_ref()
        .map(|value| value.attachment.clone());
    let namespace_path = prepared_network
        .as_ref()
        .map(|value| value.namespace_path.clone());
    let network_identity = prepared_network
        .as_ref()
        .map(|value| value.identity.clone());
    let namespace_file = prepared_network.map(|value| value.namespace_file);
    let mut spec = JailerLaunchSpec {
        sandbox_id: input.intent.key.sandbox.to_string(),
        session_id: input.intent.key.session.to_string(),
        jailer_root: input.stage.chroot_base().to_path_buf(),
        cgroup_parent: input
            .cgroup
            .path()
            .parent()
            .ok_or(Error::Path)?
            .to_path_buf(),
        uid: input.intent.uid,
        gid: input.intent.gid,
        cid: input.intent.cid,
        resources: input.resources.clone(),
        network: input.network.clone(),
        network_namespace: namespace_path.clone(),
        network_namespace_file: namespace_file,
        api_socket: input.api_socket.clone(),
    };
    journal.reserve_diagnostics(&input.resources)?;
    let jailer = build_jailer_command(&mut spec, input.runtime, input.stage, input.cgroup)?;
    let cgroup_path = jailer.cgroup.path().to_path_buf();
    let resources = input.resources.clone();
    let boot_args = super::arguments::boot_arguments(input.boot_args, input.intent)?;
    let vsock_socket = input.vsock_socket.clone();
    let jail_root = jailer
        .stage
        .chroot_base()
        .join("firecracker")
        .join(&spec.session_id)
        .join("root");
    let vsock_relative = input
        .vsock_socket
        .strip_prefix("/")
        .map_err(|_| Error::Path)?;
    if vsock_relative.as_os_str().is_empty()
        || vsock_relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(Error::Path);
    }
    let diagnostics = jailer
        .stage
        .chroot_base()
        .join("firecracker")
        .join(&spec.session_id)
        .join("jailer.stderr");
    let manifest = LaunchManifest {
        sandbox_id: spec.sandbox_id.clone(),
        session_id: spec.session_id.clone(),
        jail_root: jail_root.clone(),
        cgroup: jailer.cgroup.path().to_path_buf(),
        api_socket: jailer.api_socket_host.clone(),
        vsock_socket: jail_root.join(vsock_relative),
        api_socket_identity: None,
        vsock_socket_identity: None,
        jail_identity: jailer.stage.identity(),
        staged_jail: Some(jailer.stage.stage_manifest()),
        cgroup_identity: jailer.cgroup.identity(),
        assets: input.assets.manifest.clone(),
        jail_tree: None,
        network_identity,
        network_attachment: network_attachment.clone(),
        network_namespace: namespace_path,
    };
    if let Err(error) = journal.reserve_resources(&manifest) {
        append_diagnostic(&diagnostics, &format!("reserve_resources: {error:?}\n"));
        return Err(error);
    }
    let mut child = spawn(jailer.command)?;
    let deadline = Instant::now() + input.timeout;
    let client = match Client::new(&manifest.api_socket, input.timeout) {
        Ok(client) => client,
        Err(_) => {
            terminate(&mut child).await;
            return Err(Error::Config("invalid Firecracker API socket"));
        }
    };
    let version = match await_version(&client, deadline, &diagnostics).await {
        Ok(version) => version,
        Err(error) => {
            terminate_owned_vmm(&cgroup_path, input.runtime.firecracker.sha256.as_str()).await;
            terminate(&mut child).await;
            return Err(error);
        }
    };
    if version.firecracker_version != input.runtime.version {
        terminate_owned_vmm(&cgroup_path, input.runtime.firecracker.sha256.as_str()).await;
        terminate(&mut child).await;
        return Err(Error::Artifact("Firecracker version mismatch at launch"));
    }
    let identity = match capture_vmm(&cgroup_path, input.runtime.firecracker.sha256.as_str()) {
        Ok(identity) => identity,
        Err(error) => {
            append_diagnostic(&diagnostics, &format!("capture_vmm: {error:?}\n"));
            terminate_owned_vmm(&cgroup_path, input.runtime.firecracker.sha256.as_str()).await;
            terminate(&mut child).await;
            return Err(error);
        }
    };
    if let Err(error) = journal.record_process(&identity) {
        append_diagnostic(&diagnostics, &format!("record_process: {error:?}\n"));
        terminate_identity(&identity).await;
        terminate(&mut child).await;
        return Err(error);
    }
    if !input.restore {
        if let Err(error) = configure(
            &client,
            &ConfigureInputs {
                resources: &resources,
                boot_args: &boot_args,
                cid: input.intent.cid,
                vsock_socket: &vsock_socket,
                serial_out_path: "/run/serial.log",
                network: network_attachment.clone(),
                volumes: &input.volumes,
            },
        )
        .await
        {
            append_diagnostic(&diagnostics, &format!("configure: {error:?}\n"));
            terminate_identity(&identity).await;
            terminate(&mut child).await;
            return Err(error);
        }
        if client.start().await.is_err() {
            append_diagnostic(&diagnostics, "start: Firecracker rejected start\n");
            terminate_identity(&identity).await;
            terminate(&mut child).await;
            return Err(Error::Config("Firecracker start failed"));
        }
    } else if let Err(error) =
        super::configure::restore(&client, network_attachment.as_ref(), &vsock_socket).await
    {
        terminate_identity(&identity).await;
        terminate(&mut child).await;
        return Err(error);
    }
    let api_identity = match observe_socket(&manifest.api_socket) {
        Ok(identity) => identity,
        Err(error) => {
            append_diagnostic(&diagnostics, &format!("observe api socket: {error:?}\n"));
            terminate_identity(&identity).await;
            terminate(&mut child).await;
            return Err(error);
        }
    };
    let vsock_identity = match observe_socket(&manifest.vsock_socket) {
        Ok(identity) => identity,
        Err(error) => {
            append_diagnostic(&diagnostics, &format!("observe vsock socket: {error:?}\n"));
            terminate_identity(&identity).await;
            terminate(&mut child).await;
            return Err(error);
        }
    };
    if let Err(error) = journal.record_socket_identities(api_identity, vsock_identity) {
        append_diagnostic(
            &diagnostics,
            &format!("record_socket_identities: {error:?}\n"),
        );
        terminate_identity(&identity).await;
        terminate(&mut child).await;
        return Err(error);
    }
    let mut manifest = manifest;
    manifest.api_socket_identity = Some(api_identity);
    manifest.vsock_socket_identity = Some(vsock_identity);
    let tree = super::jail_tree::capture(
        &manifest,
        input.intent.uid,
        input.intent.gid,
        &input.runtime.firecracker.sha256,
    )
    .and_then(|tree| {
        journal.record_jail_tree(&tree)?;
        Ok(tree)
    });
    let tree = match tree {
        Ok(tree) => tree,
        Err(error) => {
            terminate_identity(&identity).await;
            terminate(&mut child).await;
            return Err(error);
        }
    };
    manifest.jail_tree = Some(tree);
    Ok(LaunchResult {
        process_record: identity.persisted(),
        process: identity,
        api_socket: manifest.api_socket.clone(),
        vsock_socket: manifest.vsock_socket.clone(),
        manifest,
    })
}

fn observe_socket(path: &Path) -> Result<AssetIdentity> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket() || metadata.file_type().is_symlink() {
        return Err(Error::Path);
    }
    Ok(AssetIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn validate_input(input: &LaunchInputs<'_>) -> Result<()> {
    if input.intent.state != sandboxd_protocol::SessionState::JailerStarting {
        return Err(Error::Config("launch intent is not in a launch state"));
    }
    if input.intent.pins.architecture != sandboxd_protocol::Architecture::X86_64 {
        return Err(Error::Config("only x86_64 launch is enabled"));
    }
    if input.timeout.is_zero() || input.timeout > Duration::from_secs(300) {
        return Err(Error::Config("invalid launch timeout"));
    }
    for socket in [&input.api_socket, &input.vsock_socket] {
        if !socket.is_absolute()
            || socket
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(Error::Path);
        }
    }
    if input.assets.manifest.root
        != input
            .stage
            .chroot_base()
            .join("firecracker")
            .join(input.intent.key.session.as_str())
            .join("root")
    {
        return Err(Error::Path);
    }
    if input.intent.key.sandbox.as_str().is_empty() {
        return Err(Error::Config("empty sandbox identity"));
    }
    Ok(())
}

async fn await_version(
    client: &Client,
    deadline: Instant,
    diagnostics: &std::path::Path,
) -> Result<firecracker_api::Version> {
    loop {
        match client.version().await {
            Ok(version) => return Ok(version),
            Err(error) if Instant::now() < deadline => {
                append_diagnostic(diagnostics, &format!("version probe: {error:?}\n"));
                sleep(Duration::from_millis(10)).await
            }
            Err(error) => {
                append_diagnostic(diagnostics, &format!("version timeout: {error:?}\n"));
                return Err(Error::Config("Firecracker API readiness timeout"));
            }
        }
    }
}

fn append_diagnostic(path: &std::path::Path, line: &str) {
    let Ok(metadata) = std::fs::metadata(path) else {
        return;
    };
    if metadata.len() >= 16 * 1024 {
        return;
    }
    let Ok(mut file) = OpenOptions::new().append(true).open(path) else {
        return;
    };
    let remaining = (16 * 1024 - metadata.len()) as usize;
    let bytes = line.as_bytes();
    let _ = file.write_all(&bytes[..bytes.len().min(remaining)]);
}

fn spawn(command: std::process::Command) -> Result<tokio::process::Child> {
    let mut command = Command::from(command);
    command.stdin(Stdio::null()).stdout(Stdio::null());
    Ok(command.spawn()?)
}

fn capture_vmm(cgroup: &Path, digest: &str) -> Result<ProcessIdentity> {
    let mut found = None;
    for pid in CgroupV2::processes_at(cgroup)? {
        let candidate = ProcessIdentity::capture(pid)?;
        if candidate.executable_sha256() == digest {
            if found.is_some() {
                return Err(Error::Config("multiple VMM processes in cgroup"));
            }
            found = Some(candidate);
        }
    }
    found.ok_or(Error::Config(
        "Firecracker process not found in owned cgroup",
    ))
}

async fn terminate(child: &mut tokio::process::Child) {
    let _ = child.kill().await;
    let _ = child.wait().await;
}

#[cfg(target_os = "linux")]
async fn terminate_owned_vmm(cgroup: &Path, digest: &str) {
    for pid in CgroupV2::processes_at(cgroup).unwrap_or_default() {
        if let Ok(identity) = ProcessIdentity::capture(pid) {
            if identity.executable_sha256() == digest {
                let _ = super::cleanup::terminate_and_wait(&identity).await;
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
async fn terminate_owned_vmm(_cgroup: &Path, _digest: &str) {}

#[cfg(target_os = "linux")]
async fn terminate_identity(identity: &ProcessIdentity) {
    let _ = super::cleanup::terminate_and_wait(identity).await;
}

#[cfg(not(target_os = "linux"))]
async fn terminate_identity(_identity: &ProcessIdentity) {}
