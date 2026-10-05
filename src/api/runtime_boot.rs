//! One bounded blocking worker prepares a boot; no permanent thread belongs to a VM.
use super::{
    runtime_authority::RuntimeAuthority, runtime_journal::RuntimeJournal, state_worker::StateClient,
};
use crate::{
    error::{Error, Result},
    jailer::{CgroupLimits, CgroupV2, JailInputs, JailStage},
    security::path::SecureDir,
    session::{AssetInputs, AssetVolume, BootInputs, BootResult, LaunchInputs, StagedAssets},
    state::{LaunchIntent, PrelaunchIntent, StateDrive},
    storage::DriveFactory,
};
use guest_protocol::{BootNonce, GUEST_PROTOCOL_VERSION, SessionIdentity};
use sandboxd_protocol::{OperationId, SandboxSpec};
use std::{path::PathBuf, sync::Arc, time::Duration};

pub(super) async fn start(
    state: StateClient,
    authority: Arc<RuntimeAuthority>,
    uid: u32,
    intent: LaunchIntent,
    spec: SandboxSpec,
    operation: OperationId,
) -> Result<BootResult> {
    start_with_snapshot(state, authority, uid, intent, spec, operation, None).await
}

pub(super) async fn start_with_snapshot(
    state: StateClient,
    authority: Arc<RuntimeAuthority>,
    uid: u32,
    intent: LaunchIntent,
    spec: SandboxSpec,
    operation: OperationId,
    restore: Option<crate::snapshot::VerifiedSnapshot>,
) -> Result<BootResult> {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let mut artifacts = authority.artifacts(&intent.pins)?;
        for (volume, pin) in artifacts.volumes.iter().zip(&intent.pins.volumes) {
            if pin.backing.is_some() && !volume.read_only {
                rustix::fs::fchown(
                    &volume.file,
                    Some(rustix::process::Uid::from_raw(intent.uid)),
                    Some(rustix::process::Gid::from_raw(intent.gid)),
                )?;
                rustix::fs::fchmod(&volume.file, rustix::fs::Mode::from_raw_mode(0o644))?;
                volume.file.sync_all()?;
            }
        }
        let execution = &authority.execution;
        let mut journal = RuntimeJournal {
            state,
            uid,
            key: intent.key.clone(),
        };
        let mut factory = DriveFactory::new(
            SecureDir::open(&execution.drive_directory)?,
            artifacts.formatter,
            authority.max_disk,
        )?;
        let prelaunch = PrelaunchIntent {
            sandbox: intent.key.sandbox.to_string(),
            session: intent.key.session.to_string(),
            sandbox_generation: intent.key.sandbox_generation.get(),
            session_generation: intent.key.generation.get(),
            operator_root: execution.operator_root.clone(),
            cgroup_parent: execution.cgroup_parent.clone(),
            firecracker_sha256: artifacts.runtime.firecracker.sha256.clone(),
            jailer_sha256: artifacts.runtime.jailer.sha256.clone(),
            stage_root: execution
                .operator_root
                .join(".inputs")
                .join(intent.key.session.as_str()),
            jail_root: execution
                .operator_root
                .join("firecracker")
                .join(intent.key.session.as_str())
                .join("root"),
            cgroup: execution.cgroup_parent.join(intent.key.session.as_str()),
            staged_jail: None,
            assets: None,
            asset_setup: None,
            cgroup_identity: None,
        };
        journal.reserve_prelaunch(prelaunch)?;
        // The durable prelaunch record must precede drive planning/creation;
        // otherwise a daemon crash can leave a state drive with no recovery
        // ownership record.
        let (key, state) = (intent.key.clone(), journal.state.clone());
        let plan = state.with_store_blocking(move |store| store.plan_state_drive(uid, &key))?;
        let drive = prepare_drive(&mut factory, &plan, &journal)?;
        let staged_volumes = artifacts
            .volumes
            .iter()
            .map(|volume| AssetVolume {
                volume_id: &volume.volume_id,
                file: &volume.file,
                read_only: volume.read_only,
            })
            .collect::<Vec<_>>();
        let stage = JailStage::prepare(
            &JailInputs {
                root: execution.operator_root.clone(),
                session_id: intent.key.session.to_string(),
                uid: intent.uid,
                gid: intent.gid,
            },
            &artifacts.runtime,
        )?;
        if let Err(error) = journal.record_prelaunch_stage(stage.stage_manifest()) {
            let _ = stage.remove_owned();
            return Err(error);
        }
        let mut assets = match StagedAssets::prepare(
            AssetInputs {
                operator_root: &execution.operator_root,
                session_id: intent.key.session.as_str(),
                kernel: &artifacts.kernel.kernel,
                initramfs: &artifacts.kernel.initramfs,
                base: &artifacts.base,
                state: &drive.file,
                volumes: &staged_volumes,
            },
            |setup| journal.record_prelaunch_asset_setup(setup.clone()),
        ) {
            Ok(assets) => assets,
            Err(error) => {
                let _ = stage.remove_owned();
                return Err(error);
            }
        };
        if let Err(error) = journal.record_prelaunch_assets(assets.manifest.clone()) {
            let _ = assets.unmount();
            let _ = stage.remove_owned();
            return Err(error);
        }
        if authority.snapshots_enabled {
            assets.prepare_snapshot_buffers(intent.uid, intent.gid, |manifest| {
                journal.record_prelaunch_assets(manifest.clone())
            })?;
        }
        let restore_identity = restore.as_ref().map(|snapshot| SessionIdentity {
            sandbox: snapshot.manifest.sandbox.clone(),
            sandbox_generation: snapshot.manifest.sandbox_generation,
            session: snapshot.manifest.session.clone(),
            session_generation: snapshot.manifest.session_generation,
            boot_nonce: snapshot.manifest.boot_nonce.clone(),
            vsock_cid: snapshot.manifest.vsock_cid,
            protocol_version: GUEST_PROTOCOL_VERSION,
        });
        if let Some(snapshot) = &restore {
            assets.prepare_snapshot_restore(
                &snapshot.memory,
                &snapshot.state,
                intent.uid,
                intent.gid,
                |manifest| journal.record_prelaunch_assets(manifest.clone()),
            )?;
        }
        let limits = match CgroupLimits::from_resources(&spec.resources) {
            Ok(limits) => limits,
            Err(error) => {
                let _ = assets.unmount();
                let _ = stage.remove_owned();
                return Err(error);
            }
        };
        let cgroup = match CgroupV2::prepare(
            &execution.cgroup_parent,
            intent.key.session.as_str(),
            limits,
        ) {
            Ok(cgroup) => cgroup,
            Err(error) => {
                let _ = assets.unmount();
                let _ = stage.remove_owned();
                return Err(error);
            }
        };
        if let Err(error) = journal.record_prelaunch_cgroup(cgroup.identity()) {
            let _ = cgroup.remove_owned();
            let _ = assets.unmount();
            let _ = stage.remove_owned();
            return Err(error);
        }
        let expected_guest = SessionIdentity {
            sandbox: intent.key.sandbox.clone(),
            sandbox_generation: intent.key.sandbox_generation,
            session: intent.key.session.clone(),
            session_generation: intent.key.generation,
            boot_nonce: BootNonce(intent.boot_nonce),
            vsock_cid: intent.cid,
            protocol_version: GUEST_PROTOCOL_VERSION,
        };
        let mut boot = handle.block_on(crate::session::boot(
            BootInputs {
                launch: LaunchInputs {
                    intent: &intent,
                    runtime: &mut artifacts.runtime,
                    kernel: &mut artifacts.kernel,
                    stage,
                    cgroup,
                    assets: &assets,
                    resources: spec.resources,
                    network: spec.network.clone(),
                    volumes: spec.volumes.clone(),
                    network_namespace_root: execution.network_namespace_root.clone(),
                    api_socket: PathBuf::from("/run/firecracker.socket"),
                    vsock_socket: PathBuf::from("/run/vsock.socket"),
                    boot_args: &execution.kernel_arguments,
                    timeout: Duration::from_secs(u64::from(execution.boot_timeout_seconds)),
                    restore: restore.is_some(),
                },
                expected_guest,
                handshake_operation: operation,
                restore_identity,
            },
            &mut journal,
        ))?;
        boot.volume_locks = artifacts.volumes;
        Ok(boot)
    })
    .await
    .map_err(|_| Error::State)?
}

fn prepare_drive(
    factory: &mut DriveFactory,
    plan: &StateDrive,
    journal: &RuntimeJournal,
) -> Result<crate::storage::PinnedDrive> {
    let owner = plan.pending_owner.ok_or(Error::State)?;
    let drive = match plan.identity {
        Some(identity) => factory.reassign(&plan.volume, identity, owner)?,
        None => {
            #[cfg(target_os = "linux")]
            {
                let (state, uid, key) = (journal.state.clone(), journal.uid, journal.key.clone());
                factory.create_journaled(&plan.volume, plan.size, owner, |identity| {
                    state.with_store_blocking(move |store| {
                        store.record_prepared_drive(uid, &key, identity)
                    })
                })?
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Err(Error::Config("drive formatting requires Linux"));
            }
        }
    };
    let (state, uid, key, identity) = (
        journal.state.clone(),
        journal.uid,
        journal.key.clone(),
        drive.identity,
    );
    state.with_store_blocking(move |store| store.record_published_drive(uid, &key, identity))?;
    Ok(drive)
}
