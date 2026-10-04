use super::{Store, guest_operation_tests::active_store};
use crate::{
    config::{LeaseConfig, Quotas},
    jailer::{CgroupIdentity, JailIdentity, JailStageManifest},
    process::PersistedProcessIdentity,
    session::{AssetIdentity, AssetsManifest, JailTreeManifest, LaunchManifest, MountedAsset},
};
use rusqlite::params;
use sandboxd_protocol::codec;
use std::path::{Path, PathBuf};

fn quotas() -> Quotas {
    Quotas {
        max_active_sandboxes: 4,
        max_booting_sandboxes: 2,
        max_sandbox_identities: 8,
        max_operation_receipts: 8,
        max_vcpus: 4,
        max_memory_mib: 1024,
        max_state_disk_mib: 1024,
    }
}

fn legacy_and_recovered(
    intent: &crate::state::LaunchIntent,
    base: &Path,
) -> (LaunchManifest, LaunchManifest) {
    let jail_root = base
        .join("firecracker")
        .join(intent.key.session.as_str())
        .join("root");
    let root_identity = AssetIdentity {
        device: 10,
        inode: 20,
    };
    let names = ["vmlinux", "initramfs", "base.img", "state.img"];
    let mut assets = names
        .iter()
        .enumerate()
        .map(|(index, name)| MountedAsset {
            path: jail_root.join(name),
            identity: AssetIdentity {
                device: 11,
                inode: 30 + index as u64,
            },
            read_only: index != 3,
            anonymous: false,
            placeholder_identity: None,
            // Simulates a legacy recovery that accidentally persisted a mount ID
            // observed in its private helper namespace.
            mount_id: Some(900 + index as u64),
        })
        .collect::<Vec<_>>();
    let jail_identity = JailIdentity {
        device: 12,
        inode: 40,
    };
    let stage_root = base.join(".inputs").join(intent.key.session.as_str());
    let stage = JailStageManifest {
        root: stage_root.clone(),
        parent: stage_root.parent().unwrap().to_path_buf(),
        firecracker: stage_root.join("firecracker"),
        ownership_manifest: stage_root.join("ownership.manifest"),
        root_identity: jail_identity,
        parent_identity: JailIdentity {
            device: 12,
            inode: 41,
        },
        firecracker_identity: JailIdentity {
            device: 12,
            inode: 42,
        },
        ownership_manifest_identity: JailIdentity {
            device: 12,
            inode: 43,
        },
        firecracker_sha256: intent.pins.firecracker_sha256.clone(),
        jailer_sha256: intent.pins.jailer_sha256.clone(),
    };
    let manifest = LaunchManifest {
        sandbox_id: intent.key.sandbox.as_str().to_owned(),
        session_id: intent.key.session.as_str().to_owned(),
        jail_root: jail_root.clone(),
        cgroup: base.join("cgroup").join(intent.key.session.as_str()),
        api_socket: jail_root.join("run/firecracker.socket"),
        vsock_socket: jail_root.join("run/vsock.socket"),
        api_socket_identity: None,
        vsock_socket_identity: None,
        jail_identity,
        staged_jail: None,
        cgroup_identity: CgroupIdentity {
            device: 13,
            inode: 44,
        },
        assets: AssetsManifest {
            root: jail_root.clone(),
            root_identity,
            root_mount_id: None,
            mount_anchor_identity: None,
            mount_anchor_id: None,
            session_identity: None,
            run_identity: None,
            mount_namespace_identity: None,
            assets: assets.clone(),
        },
        jail_tree: None,
        network_identity: None,
        network_attachment: None,
        network_namespace: None,
    };
    let mut recovered = manifest.clone();
    recovered.api_socket_identity = Some(AssetIdentity {
        device: 14,
        inode: 50,
    });
    recovered.vsock_socket_identity = Some(AssetIdentity {
        device: 14,
        inode: 51,
    });
    recovered.staged_jail = Some(stage);
    recovered.jail_tree = Some(JailTreeManifest {
        uid: intent.uid,
        gid: intent.gid,
        entries: Vec::new(),
    });
    recovered.assets.session_identity = Some(AssetIdentity {
        device: 15,
        inode: 52,
    });
    recovered.assets.run_identity = Some(AssetIdentity {
        device: 15,
        inode: 53,
    });
    recovered.assets.mount_namespace_identity = Some(AssetIdentity {
        device: 16,
        inode: 54,
    });
    for (index, asset) in assets.iter_mut().enumerate() {
        asset.placeholder_identity = Some(AssetIdentity {
            device: 15,
            inode: 60 + index as u64,
        });
        asset.mount_id = Some(70 + index as u64);
    }
    recovered.assets.assets = assets;
    (manifest, recovered)
}

#[test]
fn recovered_cleanup_manifest_survives_restart_and_retry() {
    let (directory, mut store, _, _) = active_store();
    let intent = store.session_intents(None, 10).unwrap().remove(0);
    let key = intent.key.clone();
    let (legacy, recovered) = legacy_and_recovered(&intent, directory.path());
    store
        .connection
        .execute(
            "INSERT INTO session_resources(session_id,record) VALUES (?1,?2)",
            params![key.session.as_str(), codec::encode_body(&legacy).unwrap()],
        )
        .unwrap();
    let process = PersistedProcessIdentity {
        pid: 1234,
        boot_id: intent.host_boot_id,
        start_time_ticks: 42,
        uids: [intent.uid; 4],
        gids: [intent.gid; 4],
        executable_device: 1,
        executable_inode: 2,
        executable_sha256: intent.pins.firecracker_sha256,
        cgroup_sha256: "5".repeat(64),
    };
    store
        .connection
        .execute(
            "INSERT INTO session_processes(session_id,record) VALUES (?1,?2)",
            params![key.session.as_str(), codec::encode_body(&process).unwrap()],
        )
        .unwrap();

    store
        .record_recovered_cleanup_manifest(1000, &key, &recovered)
        .expect("atomic recovery commit");
    drop(store);

    let path: PathBuf = directory.path().canonicalize().unwrap();
    let mut reopened = Store::open(&path, quotas(), LeaseConfig { max_seconds: 3600 }, 20)
        .expect("reopen store after simulated crash");
    assert_eq!(
        reopened.session_resources(1000, &key).unwrap(),
        Some(recovered.clone())
    );
    reopened
        .record_recovered_cleanup_manifest(1000, &key, &recovered)
        .expect("idempotent retry");

    let mut replaced = recovered.clone();
    replaced.assets.assets[0].mount_id = Some(999);
    assert!(
        reopened
            .record_recovered_cleanup_manifest(1000, &key, &replaced)
            .is_err()
    );
    assert_eq!(
        reopened.session_resources(1000, &key).unwrap(),
        Some(recovered)
    );
}
