use apollo_sandboxd::image::{ImageCache, ImageLimits};
use flate2::{Compression, write::GzEncoder};
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::Path};
use tar::Builder;

fn limits() -> ImageLimits {
    ImageLimits {
        max_blob_bytes: 1 << 20,
        max_cache_bytes: 8 << 20,
        max_layers: 8,
        max_entries: 64,
        max_uncompressed_bytes: 2 << 20,
    }
}

fn blob(root: &Path, bytes: &[u8]) -> (String, u64) {
    let digest = format!("sha256:{:x}", Sha256::digest(bytes));
    let path = root.join("blobs/sha256").join(&digest[7..]);
    fs::write(path, bytes).expect("blob");
    (digest, bytes.len() as u64)
}

fn tar_layer(gzip: bool, entries: impl FnOnce(&mut Builder<Vec<u8>>)) -> Vec<u8> {
    let mut builder = Builder::new(Vec::new());
    entries(&mut builder);
    let raw = builder.into_inner().expect("tar");
    if gzip {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&raw).expect("gzip");
        encoder.finish().expect("gzip finish")
    } else {
        raw
    }
}

fn file(builder: &mut Builder<Vec<u8>>, name: &str, value: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_path(name).expect("path");
    header.set_size(value.len() as u64);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, value).expect("entry");
}

fn pax_file(builder: &mut Builder<Vec<u8>>, name: &str, key: &str, value: &[u8]) {
    builder
        .append_pax_extensions([(key, value)])
        .expect("pax extension");
    file(builder, name, b"payload");
}

fn symlink(builder: &mut Builder<Vec<u8>>, name: &str, target: &str) {
    let mut header = tar::Header::new_gnu();
    header.set_path(name).expect("path");
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_link_name(target).expect("target");
    header.set_size(0);
    header.set_uid(0);
    header.set_gid(0);
    header.set_cksum();
    builder.append(&header, &[][..]).expect("symlink");
}

fn layout(layer: &[u8]) -> tempfile::TempDir {
    layout_layers(&[layer])
}

fn layout_layers(layers: &[&[u8]]) -> tempfile::TempDir {
    let directory = tempfile::tempdir_in(
        std::env::temp_dir()
            .canonicalize()
            .expect("temporary directory"),
    )
    .expect("layout");
    fs::create_dir_all(directory.path().join("blobs/sha256")).expect("blobs");
    let descriptors: Vec<_> = layers
        .iter()
        .map(|layer| {
            let (digest, size) = blob(directory.path(), layer);
            let media_type = if layer.starts_with(&[0x1f, 0x8b]) {
                "application/vnd.oci.image.layer.v1.tar+gzip"
            } else {
                "application/vnd.oci.image.layer.v1.tar"
            };
            serde_json::json!({"mediaType":media_type,"digest":digest,"size":size})
        })
        .collect();
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "layers": descriptors
    });
    let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest");
    let (manifest_digest, manifest_size) = blob(directory.path(), &manifest_bytes);
    let index = serde_json::json!({"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":manifest_digest,"size":manifest_size,"platform":{"os":"linux","architecture":std::env::consts::ARCH}}]});
    fs::write(
        directory.path().join("index.json"),
        serde_json::to_vec(&index).expect("index"),
    )
    .expect("index");
    directory
}

#[test]
fn layout_import_applies_gzip_layer_and_whiteout() {
    let layer = tar_layer(true, |builder| {
        file(builder, "etc/.wh.old", b"");
        file(builder, "etc/new", b"new");
    });
    let layout = layout(&layer);
    let cache = ImageCache::open(layout.path().join("cache"), limits()).expect("cache");
    let imported = cache.import_layout(layout.path()).expect("import");
    assert!(!imported.rootfs.join("etc/old").exists());
    assert_eq!(
        fs::read(imported.rootfs.join("etc/new")).expect("new"),
        b"new"
    );
}

#[test]
fn traversal_and_device_entries_are_rejected_without_host_write() {
    let layer = tar_layer(false, |builder| {
        symlink(builder, "escape", "../../escaped");
    });
    let layout = layout(&layer);
    let outside = layout.path().join("escaped");
    let cache = ImageCache::open(layout.path().join("cache"), limits()).expect("cache");
    assert!(cache.import_layout(layout.path()).is_err());
    assert!(!outside.exists());
}

#[test]
fn whiteout_cannot_delete_host_file_through_guest_absolute_symlink() {
    let foreign = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let victim = foreign.path().join("victim");
    fs::write(&victim, b"unrelated-host-file").unwrap();
    let first = tar_layer(false, |builder| {
        symlink(builder, "escape", foreign.path().to_str().unwrap());
    });
    let second = tar_layer(false, |builder| {
        file(builder, "escape/.wh.victim", b"");
    });
    let layout = layout_layers(&[&first, &second]);
    let cache = ImageCache::open(layout.path().join("cache"), limits()).unwrap();
    let result = cache.import_layout(layout.path());
    assert_eq!(
        fs::read(&victim).expect("host victim must survive"),
        b"unrelated-host-file"
    );
    assert!(result.is_err(), "whiteout parent symlink must be rejected");
}

#[test]
fn malformed_whiteout_cannot_delete_parent_of_temporary_rootfs() {
    let layer = tar_layer(false, |builder| {
        file(builder, ".wh...", b"");
    });
    let layout = layout(&layer);
    let sentinel = layout.path().join("cache-sentinel");
    fs::write(&sentinel, b"unrelated-cache-file").unwrap();
    let cache = ImageCache::open(layout.path().join("cache"), limits()).unwrap();
    assert!(cache.import_layout(layout.path()).is_err());
    assert_eq!(
        fs::read(&sentinel).expect("cache parent sentinel must survive"),
        b"unrelated-cache-file"
    );
}

#[test]
fn expansion_limit_is_aggregate_across_layers() {
    let contents = vec![b'x'; 600 * 1024];
    let first = tar_layer(false, |builder| file(builder, "first", &contents));
    let second = tar_layer(false, |builder| file(builder, "second", &contents));
    let layout = layout_layers(&[&first, &second]);
    let mut bounded = limits();
    bounded.max_uncompressed_bytes = 1 << 20;
    let cache = ImageCache::open(layout.path().join("cache"), bounded).unwrap();
    assert!(cache.import_layout(layout.path()).is_err());
}

#[test]
fn privileged_host_xattrs_are_rejected() {
    let layer = tar_layer(false, |builder| {
        pax_file(
            builder,
            "victim",
            "SCHILY.xattr.trusted.overlay.opaque",
            b"y",
        );
    });
    let layout = layout(&layer);
    let cache = ImageCache::open(layout.path().join("cache"), limits()).unwrap();
    assert!(cache.import_layout(layout.path()).is_err());
}

#[test]
fn oversized_pax_metadata_is_rejected_before_application() {
    let value = vec![b'x'; 70 * 1024];
    let layer = tar_layer(false, |builder| {
        pax_file(builder, "victim", "comment", &value);
    });
    let layout = layout(&layer);
    let cache = ImageCache::open(layout.path().join("cache"), limits()).unwrap();
    assert!(cache.import_layout(layout.path()).is_err());
}
