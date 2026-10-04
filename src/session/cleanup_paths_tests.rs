use super::{AssetIdentity, AssetsManifest};
use std::{fs, os::unix::fs::MetadataExt, path::Path};

fn identity(path: &Path) -> AssetIdentity {
    let meta = fs::symlink_metadata(path).unwrap();
    AssetIdentity {
        device: meta.dev(),
        inode: meta.ino(),
    }
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
fn detached_asset_placeholder_replays_but_replacement_is_rejected() {
    let (_outer, mut assets) = fixture();
    assets.mount_namespace_identity =
        Some(super::asset_mount::current_namespace_identity().unwrap());
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
