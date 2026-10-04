//! Anonymous snapshot buffers are mounted before the jailer isolates its namespace.
use super::{AssetsManifest, MountedAsset, StagedAssets};
use crate::error::{Error, Result};
use std::{
    fs::File,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
};

impl StagedAssets {
    pub(crate) fn prepare_snapshot_buffers(
        &mut self,
        uid: u32,
        gid: u32,
        mut persist: impl FnMut(&AssetsManifest) -> Result<()>,
    ) -> Result<()> {
        for name in ["snapshot-memory", "snapshot-state"] {
            let file = anonymous(uid, gid)?;
            self.mount_snapshot_buffer(&file, name, false, &mut persist)?;
        }
        Ok(())
    }
    pub(crate) fn prepare_snapshot_restore(
        &mut self,
        memory: &File,
        state: &File,
        uid: u32,
        gid: u32,
        mut persist: impl FnMut(&AssetsManifest) -> Result<()>,
    ) -> Result<()> {
        for (file, name) in [(memory, "restore-memory"), (state, "restore-state")] {
            own(file, uid, gid)?;
            self.mount_snapshot_buffer(file, name, true, &mut persist)?;
        }
        Ok(())
    }
    fn mount_snapshot_buffer(
        &mut self,
        file: &File,
        name: &str,
        read_only: bool,
        persist: &mut impl FnMut(&AssetsManifest) -> Result<()>,
    ) -> Result<()> {
        let root = super::asset_verify::open_root(&self.manifest)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 0 {
            return Err(Error::Path);
        }
        let path = self.manifest.root.join(name);
        let placeholder = File::from(rustix::fs::openat(
            &root,
            name,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )?);
        let placeholder_identity = super::assets::identity(&placeholder.metadata()?);
        placeholder.sync_all()?;
        rustix::fs::fsync(&root)?;
        self.manifest.assets.push(MountedAsset {
            path: path.clone(),
            identity: super::assets::identity(&metadata),
            read_only,
            placeholder_identity: Some(placeholder_identity),
            mount_id: None,
            anonymous: true,
        });
        // The source identity is durable before the mount can retain plaintext across a crash.
        persist(&self.manifest)?;
        super::asset_mount::bind_fd(file, &path)?;
        if read_only {
            super::asset_mount::remount_read_only(&path)?;
        }
        self.manifest
            .assets
            .last_mut()
            .ok_or(Error::State)?
            .mount_id = Some(super::asset_mount::observed_id(&path)?);
        persist(&self.manifest)
    }
}

pub(crate) fn open_capture(manifest: &AssetsManifest, name: &str) -> Result<File> {
    if !matches!(name, "snapshot-memory" | "snapshot-state") {
        return Err(Error::Path);
    }
    let path = manifest.root.join(name);
    let expected = manifest
        .assets
        .iter()
        .find(|asset| asset.path == path && asset.anonymous && !asset.read_only)
        .ok_or(Error::Path)?;
    let root = super::asset_verify::open_root(manifest)?;
    let file = File::from(rustix::fs::openat(
        &root,
        name,
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?);
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 0
        || super::assets::identity(&metadata) != expected.identity
        || Some(super::asset_mount::observed_id(Path::new(&format!(
            "/proc/self/fd/{}/{}",
            root.as_raw_fd(),
            name
        )))?)
            != expected.mount_id
    {
        return Err(Error::Path);
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn anonymous(uid: u32, gid: u32) -> Result<File> {
    let fd = rustix::fs::memfd_create(
        "apollo-snapshot-capture",
        rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
    )?;
    let file = File::from(fd);
    own(&file, uid, gid)?;
    Ok(file)
}
#[cfg(not(target_os = "linux"))]
fn anonymous(_: u32, _: u32) -> Result<File> {
    Err(Error::Config("snapshot buffers require Linux"))
}

fn own(file: &File, uid: u32, gid: u32) -> Result<()> {
    rustix::fs::fchown(
        file,
        Some(rustix::process::Uid::from_raw(uid)),
        Some(rustix::process::Gid::from_raw(gid)),
    )?;
    rustix::fs::fchmod(file, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR)?;
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use rustix::fs::{MemfdFlags, SealFlags};
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::unix::fs::FileExt,
    };

    struct MountedFixture(StagedAssets);
    impl Drop for MountedFixture {
        fn drop(&mut self) {
            let _ = super::super::assets::unmount_manifest_assets(&self.0.manifest);
        }
    }

    #[test]
    #[ignore = "requires root and a private Linux mount namespace with tmpfs at /run"]
    fn native_snapshot_buffers_retain_anonymous_bytes_and_cleanup() {
        let directory = tempfile::tempdir_in("/run").unwrap();
        let root = directory.path().join("root");
        fs::create_dir(&root).unwrap();
        let identity = super::super::assets::identity;
        let mut fixture = MountedFixture(StagedAssets {
            manifest: AssetsManifest {
                root: root.clone(),
                root_identity: identity(&fs::metadata(&root).unwrap()),
                root_mount_id: None,
                mount_anchor_identity: None,
                mount_anchor_id: None,
                session_identity: Some(identity(&directory.path().metadata().unwrap())),
                run_identity: None,
                mount_namespace_identity: Some(
                    super::super::asset_mount::current_namespace_identity().unwrap(),
                ),
                assets: vec![],
            },
        });
        fixture
            .0
            .prepare_snapshot_buffers(200_000, 200_000, |_| Ok(()))
            .unwrap();
        // The creation descriptors are closed; the mounts must retain both buffers.
        for name in ["snapshot-memory", "snapshot-state"] {
            let file = open_capture(&fixture.0.manifest, name).unwrap();
            file.write_all_at(b"captured bytes", 0).unwrap();
            assert_eq!(fs::read(root.join(name)).unwrap(), b"captured bytes");
        }
        let mut source = File::from(
            rustix::fs::memfd_create(
                "snapshot-mount-test",
                MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
            )
            .unwrap(),
        );
        source.write_all(b"authenticated bytes").unwrap();
        rustix::fs::fcntl_add_seals(
            &source,
            SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
        )
        .unwrap();
        fixture
            .0
            .prepare_snapshot_restore(&source, &source, 200_000, 200_000, |_| Ok(()))
            .unwrap();
        drop(source);
        for name in ["restore-memory", "restore-state"] {
            assert_eq!(fs::read(root.join(name)).unwrap(), b"authenticated bytes");
            let error = OpenOptions::new()
                .write(true)
                .open(root.join(name))
                .unwrap_err();
            assert_eq!(
                error.raw_os_error(),
                Some(rustix::io::Errno::ROFS.raw_os_error())
            );
        }
        // Serialize the ownership ledger as recovery does; no creation FD is retained.
        let recovered: AssetsManifest =
            serde_json::from_slice(&serde_json::to_vec(&fixture.0.manifest).unwrap()).unwrap();
        for asset in &recovered.assets {
            let metadata = fs::metadata(&asset.path).unwrap();
            assert_eq!(metadata.nlink(), 0);
            assert_eq!(metadata.uid(), 200_000);
            assert_eq!(metadata.gid(), 200_000);
            assert_eq!(identity(&metadata), asset.identity);
            assert!(asset.mount_id.is_some());
        }
        super::super::assets::unmount_manifest_assets(&recovered).unwrap();
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        super::super::assets::unmount_manifest_assets(&recovered).unwrap();
    }
}
