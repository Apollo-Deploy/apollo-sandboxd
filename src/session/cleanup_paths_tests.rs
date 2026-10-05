use super::{AssetIdentity, AssetsManifest};
use std::{
    env, fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::Command,
};

fn identity(path: &Path) -> AssetIdentity {
    let meta = fs::symlink_metadata(path).unwrap();
    AssetIdentity {
        device: meta.dev(),
        inode: meta.ino(),
    }
}

const ISOLATED_NAMESPACE_ENV: &str = "APOLLO_SANDBOXD_CLEANUP_TEST_ISOLATED_NS";

fn run_in_isolated_namespace(test_filter: &str) -> bool {
    if env::var_os(ISOLATED_NAMESPACE_ENV).is_some() {
        return false;
    }
    assert_eq!(rustix::process::geteuid().as_raw(), 0, "requires root");
    let output = Command::new("/usr/bin/unshare")
        .args(["--mount", "--propagation", "private", "--"])
        .arg(std::env::current_exe().expect("test executable"))
        .args(["--ignored", "--nocapture", "--test-threads=1"])
        .arg(test_filter)
        .env(ISOLATED_NAMESPACE_ENV, "1")
        .output()
        .expect("start isolated mount namespace; requires util-linux unshare");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains(test_filter),
        "isolated test failed or did not run: {stdout}\n{stderr}"
    );
    println!("{stdout}");
    true
}

fn fixture() -> (tempfile::TempDir, AssetsManifest) {
    let outer = tempfile::tempdir().unwrap();
    let parent = outer.path().canonicalize().unwrap().join("session");
    let root = parent.join("root");
    fs::create_dir_all(root.join("run")).unwrap();
    let assets = AssetsManifest {
        root_identity: identity(&root),
        root_mount_id: None,
        mount_anchor_identity: None,
        mount_anchor_id: None,
        session_identity: Some(identity(&parent)),
        run_identity: Some(identity(&root.join("run"))),
        mount_namespace_identity: None,
        root,
        assets: Vec::new(),
    };
    (outer, assets)
}

#[test]
fn directory_cleanup_replays_after_each_partial_stage() {
    for stage in 0..4 {
        let (_outer, assets) = fixture();
        if stage >= 1 {
            fs::remove_dir(assets.root.join("run")).unwrap();
        }
        if stage >= 2 {
            fs::remove_dir(&assets.root).unwrap();
        }
        if stage >= 3 {
            fs::remove_dir(assets.root.parent().unwrap()).unwrap();
        }
        super::cleanup_paths::remove_empty_directories(&assets).unwrap();
        super::cleanup_paths::remove_empty_directories(&assets).unwrap();
        assert!(!assets.root.parent().unwrap().exists());
    }
}

#[test]
fn replacement_run_and_unknown_files_are_preserved() {
    let (_outer, assets) = fixture();
    let run = assets.root.join("run");
    fs::rename(&run, assets.root.join("original-run")).unwrap();
    fs::create_dir(&run).unwrap();
    fs::write(run.join("foreign"), b"preserve").unwrap();
    assert!(matches!(
        super::cleanup_paths::remove_empty_directories(&assets),
        Err(crate::error::Error::Path)
    ));
    assert_eq!(fs::read(run.join("foreign")).unwrap(), b"preserve");
}

#[test]
#[cfg(target_os = "linux")]
#[ignore = "native Linux asset cleanup; requires root, CAP_SYS_ADMIN, and util-linux"]
fn detached_asset_placeholder_replays_but_replacement_is_rejected() {
    if run_in_isolated_namespace("detached_asset_placeholder_replays_but_replacement_is_rejected") {
        return;
    }
    let outer = tempfile::tempdir().unwrap();
    let anchor = outer.path().join("firecracker");
    fs::create_dir(&anchor).unwrap();
    fs::set_permissions(&anchor, fs::Permissions::from_mode(0o700)).unwrap();
    rustix::mount::mount_bind_recursive(&anchor, &anchor).unwrap();
    rustix::mount::mount_change(
        &anchor,
        rustix::mount::MountPropagationFlags::PRIVATE | rustix::mount::MountPropagationFlags::REC,
    )
    .unwrap();
    let anchor_mount_id = super::asset_mount::ensure_private_anchor(&anchor).unwrap();
    let session = anchor.join("session");
    let root = session.join("root");
    fs::create_dir_all(root.join("run")).unwrap();
    for path in [&session, &root, &root.join("run")] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let root_mount_id = super::asset_mount::create_private_root(&root).unwrap();
    assert_ne!(root_mount_id, anchor_mount_id);
    let mut assets = AssetsManifest {
        root_identity: identity(&root),
        root_mount_id: None,
        mount_anchor_identity: Some(identity(&anchor)),
        mount_anchor_id: Some(anchor_mount_id),
        session_identity: Some(identity(&session)),
        run_identity: Some(identity(&root.join("run"))),
        mount_namespace_identity: Some(super::asset_mount::current_namespace_identity().unwrap()),
        root,
        assets: Vec::new(),
    };
    let original = assets.root.join("base.img");
    let file = fs::File::create(&original).unwrap();
    let placeholder = identity(&original);
    assets.assets.push(super::MountedAsset {
        path: original.clone(),
        identity: AssetIdentity {
            device: 999,
            inode: 999,
        },
        read_only: true,
        anonymous: false,
        placeholder_identity: Some(placeholder),
        mount_id: Some(123),
    });
    super::assets::unmount_manifest_assets(&assets).unwrap();
    super::assets::unmount_manifest_assets(&assets).unwrap();
    assert!(!original.exists());
    // Retain the old inode through `file`; a new path cannot alias it by reuse.
    fs::write(&original, b"foreign").unwrap();
    assert!(matches!(
        super::assets::unmount_manifest_assets(&assets),
        Err(crate::error::Error::Path)
    ));
    assert_eq!(fs::read(&original).unwrap(), b"foreign");
    drop(file);
    fs::remove_file(&original).unwrap();
    super::asset_mount::unmount(&assets.root).unwrap();
    fs::remove_dir(assets.root.join("run")).unwrap();
    fs::remove_dir(&assets.root).unwrap();
    fs::remove_dir(&session).unwrap();
    super::asset_mount::unmount(&anchor).unwrap();
    fs::remove_dir(&anchor).unwrap();
}

#[test]
#[cfg(target_os = "linux")]
fn wrong_mount_namespace_never_unlinks_a_detached_placeholder() {
    let (_outer, mut assets) = fixture();
    let original = assets.root.join("base.img");
    fs::File::create(&original).unwrap();
    let placeholder = identity(&original);
    assets.assets.push(super::MountedAsset {
        path: original.clone(),
        identity: AssetIdentity {
            device: 999,
            inode: 999,
        },
        read_only: true,
        anonymous: false,
        placeholder_identity: Some(placeholder),
        mount_id: Some(123),
    });
    assets.mount_namespace_identity = Some(AssetIdentity {
        device: 999,
        inode: 999,
    });

    assert!(matches!(
        super::assets::unmount_manifest_assets(&assets),
        Err(crate::error::Error::Path)
    ));
    assert!(original.exists());
}

#[test]
#[cfg(target_os = "linux")]
fn wrong_mount_namespace_never_accepts_a_missing_session_tree() {
    let (_outer, mut assets) = fixture();
    assets.assets.push(super::MountedAsset {
        path: assets.root.join("base.img"),
        identity: AssetIdentity {
            device: 999,
            inode: 999,
        },
        read_only: true,
        anonymous: false,
        placeholder_identity: Some(AssetIdentity {
            device: 998,
            inode: 998,
        }),
        mount_id: Some(123),
    });
    assets.mount_namespace_identity = Some(AssetIdentity {
        device: 999,
        inode: 999,
    });
    fs::remove_dir_all(assets.root.parent().unwrap()).unwrap();

    assert!(matches!(
        super::assets::unmount_manifest_assets(&assets),
        Err(crate::error::Error::Path)
    ));
}
