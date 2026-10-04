//! Descriptor-pinned operator volume catalog resolution.
use crate::{
    config::{VolumeCatalog, VolumeCatalogEntry},
    error::{Error, Result},
    security::path::SecureDir,
    state::VolumePin,
};
use sandboxd_protocol::Volume;
use std::{fs::File, os::unix::fs::MetadataExt};

pub(crate) struct PinnedVolume {
    pub volume_id: String,
    pub file: File,
    pub read_only: bool,
}

pub(crate) fn capture(catalog: &VolumeCatalog, requested: &[Volume]) -> Result<Vec<VolumePin>> {
    let mut total = 0_u64;
    let mut pins = Vec::with_capacity(requested.len());
    let mut opened = Vec::with_capacity(requested.len());
    for volume in requested {
        let entry = entry(catalog, &volume.catalog_key)?;
        if !entry.writable && !volume.read_only {
            return Err(Error::Config("read-only catalog volume requested writable"));
        }
        let pinned = open(entry, volume.read_only)?;
        total = total
            .checked_add(pinned.size_bytes)
            .filter(|value| *value <= catalog.max_total_bytes)
            .ok_or(Error::Config("aggregate volume size limit"))?;
        pins.push(VolumePin {
            volume_id: volume.id.clone(),
            catalog_key: volume.catalog_key.clone(),
            device: pinned.device,
            inode: pinned.inode,
            size_bytes: pinned.size_bytes,
            catalog_read_only: !entry.writable,
            read_only: volume.read_only,
        });
        opened.push(pinned.file);
    }
    drop(opened);
    Ok(pins)
}

/// Reopens only the configured entry named by a persisted catalog key and
/// reacquires a shared or exclusive lock for the entire boot lifecycle.
pub(crate) fn reopen(catalog: &VolumeCatalog, pins: &[VolumePin]) -> Result<Vec<PinnedVolume>> {
    let mut total = 0_u64;
    pins.iter()
        .map(|pin| {
            let entry = entry(catalog, &pin.catalog_key)?;
            if pin.catalog_read_only == entry.writable || (!entry.writable && !pin.read_only) {
                return Err(Error::State);
            }
            let pinned = open(entry, pin.read_only)?;
            if pinned.device != pin.device
                || pinned.inode != pin.inode
                || pinned.size_bytes != pin.size_bytes
            {
                return Err(Error::Artifact("catalog volume identity changed"));
            }
            total = total
                .checked_add(pinned.size_bytes)
                .filter(|value| *value <= catalog.max_total_bytes)
                .ok_or(Error::Config("aggregate volume size limit"))?;
            Ok(PinnedVolume {
                volume_id: pin.volume_id.to_string(),
                file: pinned.file,
                read_only: pin.read_only,
            })
        })
        .collect()
}

fn entry<'a>(catalog: &'a VolumeCatalog, key: &str) -> Result<&'a VolumeCatalogEntry> {
    catalog
        .entries
        .iter()
        .find(|entry| entry.key == key)
        .ok_or(Error::Config("volume catalog key unavailable"))
}

fn open(entry: &VolumeCatalogEntry, read_only: bool) -> Result<OpenVolume> {
    let parent = entry.path.parent().ok_or(Error::Path)?;
    let name = entry
        .path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(Error::Path)?;
    let directory = SecureDir::open(parent)?;
    let file = directory.open_file(name, !read_only)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > entry.max_bytes
    {
        return Err(Error::Artifact(
            "catalog volume is not a bounded private regular file",
        ));
    }
    let lock = if read_only {
        rustix::fs::FlockOperation::NonBlockingLockShared
    } else {
        rustix::fs::FlockOperation::NonBlockingLockExclusive
    };
    rustix::fs::flock(&file, lock).map_err(|_| Error::Locked)?;
    Ok(OpenVolume {
        file,
        device: metadata.dev(),
        inode: metadata.ino(),
        size_bytes: metadata.len(),
    })
}

struct OpenVolume {
    file: File,
    device: u64,
    inode: u64,
    size_bytes: u64,
}

pub(crate) fn staged_name(volume_id: &str) -> Result<String> {
    sandboxd_protocol::VolumeId::new(volume_id.to_owned()).map_err(|_| Error::State)?;
    Ok(format!("volume-{volume_id}.img"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandboxd_protocol::VolumeId;
    use std::{fs, path::PathBuf};
    use tempfile::TempDir;

    fn tempdir() -> TempDir {
        tempfile::Builder::new()
            .prefix("volume-catalog-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap()
    }

    fn entry_for(path: PathBuf, writable: bool) -> VolumeCatalogEntry {
        VolumeCatalogEntry {
            key: "data".into(),
            path,
            max_bytes: 4096,
            writable,
        }
    }

    fn request(read_only: bool) -> Volume {
        Volume {
            id: VolumeId::new("data".to_owned()).unwrap(),
            catalog_key: "data".into(),
            read_only,
            guest_mount_point: "/data".into(),
            filesystem: "ext4".into(),
            rate_limiter: None,
        }
    }

    fn catalog(path: PathBuf, writable: bool) -> VolumeCatalog {
        VolumeCatalog {
            max_total_bytes: 4096,
            entries: vec![entry_for(path, writable)],
        }
    }

    #[test]
    fn accepts_and_reopens_a_catalogued_read_only_volume() {
        let dir = tempdir();
        let path = dir.path().join("disk.img");
        fs::write(&path, [7_u8; 512]).unwrap();
        let catalog = catalog(path, true);
        let pins = capture(&catalog, &[request(true)]).unwrap();
        assert_eq!(pins[0].catalog_key, "data");
        assert_eq!(pins[0].size_bytes, 512);
        let attached = reopen(&catalog, &pins).unwrap();
        assert_eq!(attached[0].volume_id, "data");
        assert!(attached[0].read_only);
        assert_eq!(
            staged_name(&attached[0].volume_id).unwrap(),
            "volume-data.img"
        );
    }

    #[test]
    fn rejects_symlinks_replaced_inodes_and_unsafe_shared_writes() {
        let dir = tempdir();
        let real = dir.path().join("real.img");
        fs::write(&real, [1_u8; 512]).unwrap();
        let link = dir.path().join("link.img");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(capture(&catalog(link, true), &[request(true)]).is_err());

        let path = dir.path().join("disk.img");
        fs::write(&path, [2_u8; 512]).unwrap();
        let replacement = dir.path().join("replacement.img");
        fs::write(&replacement, [3_u8; 512]).unwrap();
        let configured = catalog(path.clone(), true);
        let pins = capture(&configured, &[request(true)]).unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert!(reopen(&configured, &pins).is_err());

        assert!(capture(&catalog(real, false), &[request(false)]).is_err());
    }

    #[test]
    fn writable_catalog_entries_require_an_exclusive_boot_lock() {
        let dir = tempdir();
        let path = dir.path().join("disk.img");
        fs::write(&path, [8_u8; 512]).unwrap();
        let catalog = catalog(path, true);
        let mut writable = request(false);
        writable.id = VolumeId::new("write".to_owned()).unwrap();
        let pins = capture(&catalog, &[writable]).unwrap();
        let held = reopen(&catalog, &pins).unwrap();
        assert!(reopen(&catalog, &pins).is_err());
        drop(held);
        assert!(reopen(&catalog, &pins).is_ok());
    }

    #[test]
    fn rejects_hard_links_and_aggregate_size_overflow() {
        let dir = tempdir();
        let path = dir.path().join("disk.img");
        fs::write(&path, [4_u8; 512]).unwrap();
        let hard_link = dir.path().join("other.img");
        fs::hard_link(&path, &hard_link).unwrap();
        assert!(capture(&catalog(path.clone(), true), &[request(true)]).is_err());

        fs::remove_file(hard_link).unwrap();
        let mut limited = catalog(path, true);
        limited.max_total_bytes = 511;
        assert!(capture(&limited, &[request(true)]).is_err());

        let empty = dir.path().join("empty.img");
        fs::File::create(&empty).unwrap();
        assert!(capture(&catalog(empty, true), &[request(true)]).is_err());
    }
}
