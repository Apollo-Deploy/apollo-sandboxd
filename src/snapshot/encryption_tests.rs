use super::{
    ArtifactContext, ArtifactKind, LocalKey, SnapshotKey, SnapshotSecretPolicy,
    encryption::{decrypt_stream, encrypt},
};
use sandboxd_protocol::{SandboxGeneration, SandboxId, SessionGeneration, SessionId, SnapshotId};
use sha2::{Digest, Sha256};
use std::{fs, io::Cursor, os::unix::fs::PermissionsExt};

fn context() -> ArtifactContext {
    ArtifactContext {
        snapshot: SnapshotId::new("snap-one").unwrap(),
        sandbox: SandboxId::new("sandbox-one").unwrap(),
        sandbox_generation: SandboxGeneration::new(3).unwrap(),
        session: SessionId::new("session-one").unwrap(),
        session_generation: SessionGeneration::new(9).unwrap(),
        kind: ArtifactKind::Memory,
    }
}
fn ciphertext(data: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    encrypt(
        data,
        &mut output,
        &SnapshotKey::fixture([19; 32]),
        &context(),
        data.len() as u64,
    )
    .unwrap();
    output
}
fn decode(bytes: &[u8], size: u64) -> crate::error::Result<Vec<u8>> {
    let mut output = Vec::new();
    decrypt_stream(
        bytes,
        &mut output,
        &SnapshotKey::fixture([19; 32]),
        &context(),
        size,
    )?;
    Ok(output)
}

#[test]
fn binary_empty_and_multiple_records_round_trip_with_digest() {
    for size in [0, 1, 65_535, 65_536, 65_537, 196_611] {
        let data: Vec<_> = (0..size).map(|n| (n % 256) as u8).collect();
        let mut encrypted = Vec::new();
        let digest = encrypt(
            data.as_slice(),
            &mut encrypted,
            &SnapshotKey::fixture([19; 32]),
            &context(),
            size as u64,
        )
        .unwrap();
        assert_eq!(digest, hex::encode(Sha256::digest(&data)));
        let mut output = Vec::new();
        let decoded_digest = decrypt_stream(
            encrypted.as_slice(),
            &mut output,
            &SnapshotKey::fixture([19; 32]),
            &context(),
            size as u64,
        )
        .unwrap();
        assert_eq!(decoded_digest, digest);
        assert_eq!(output, data);
    }
}

#[test]
fn every_header_field_and_record_is_authenticated() {
    let data = vec![77; 65_537];
    let encrypted = ciphertext(&data);
    for index in [0, 7, 8, 12, 19, 20, 35, 36, 65_572, encrypted.len() - 1] {
        let mut attack = encrypted.clone();
        attack[index] ^= 1;
        assert!(decode(&attack, data.len() as u64).is_err(), "index {index}");
    }
    assert!(decode(&encrypted, data.len() as u64 - 1).is_err());
    let mut wrong_key_output = Vec::new();
    assert!(
        decrypt_stream(
            encrypted.as_slice(),
            &mut wrong_key_output,
            &SnapshotKey::fixture([18; 32]),
            &context(),
            data.len() as u64
        )
        .is_err()
    );
    for alteration in 0..4 {
        let mut identity = context();
        match alteration {
            0 => identity.snapshot = SnapshotId::new("other").unwrap(),
            1 => identity.sandbox_generation = SandboxGeneration::new(4).unwrap(),
            2 => identity.session_generation = SessionGeneration::new(10).unwrap(),
            _ => identity.kind = ArtifactKind::State,
        }
        assert!(
            decrypt_stream(
                encrypted.as_slice(),
                Vec::new(),
                &SnapshotKey::fixture([19; 32]),
                &identity,
                data.len() as u64
            )
            .is_err()
        );
    }
}

#[test]
fn truncation_append_and_record_reordering_fail() {
    let encrypted = ciphertext(&vec![8; 131_072]);
    for size in [0, 35, 36, 65_587, encrypted.len() - 16, encrypted.len() - 1] {
        assert!(decode(&encrypted[..size], 131_072).is_err());
    }
    let mut appended = encrypted.clone();
    appended.push(0);
    assert!(decode(&appended, 131_072).is_err());
    let mut reordered = encrypted.clone();
    let record_size = 65_536 + 16;
    reordered[36..36 + record_size]
        .copy_from_slice(&encrypted[36 + record_size..36 + 2 * record_size]);
    reordered[36 + record_size..36 + 2 * record_size]
        .copy_from_slice(&encrypted[36..36 + record_size]);
    assert!(decode(&reordered, 131_072).is_err());
    let mut duplicate = encrypted.clone();
    duplicate[36 + record_size..36 + 2 * record_size]
        .copy_from_slice(&encrypted[36..36 + record_size]);
    assert!(decode(&duplicate, 131_072).is_err());
    assert!(decode(&ciphertext(&[])[..36], 0).is_err());
}

#[test]
fn plaintext_size_limits_and_input_size_are_enforced() {
    let key = SnapshotKey::fixture([19; 32]);
    let mut identity = context();
    identity.kind = ArtifactKind::Manifest;
    assert!(encrypt(Cursor::new([]), Vec::new(), &key, &identity, 256 * 1024 + 1).is_err());
    assert!(decrypt_stream(Cursor::new([]), Vec::new(), &key, &identity, u64::MAX).is_err());
    assert!(encrypt(b"abc".as_slice(), Vec::new(), &key, &context(), 2).is_err());
    assert!(encrypt(b"abc".as_slice(), Vec::new(), &key, &context(), 4).is_err());
    assert_ne!(ciphertext(b"same"), ciphertext(b"same"));
}

#[test]
fn local_key_rejects_empty_permissive_and_symlink_objects() {
    let root = tempfile::Builder::new()
        .prefix("snapshot-key-test-")
        .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .unwrap();
    let directory = root.path().canonicalize().unwrap();
    let path = directory.join("key");
    fs::write(&path, []).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(LocalKey::open(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), Vec::<u8>::new());
    fs::write(&path, [7; 32]).unwrap();
    assert!(LocalKey::open(&path).is_ok());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(LocalKey::open(&path).is_err());
    let link = directory.join("alias");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(LocalKey::open(&link).is_err());
}

#[test]
fn secrets_require_explicit_encrypted_policy() {
    assert!(SnapshotSecretPolicy::default().authorize(true).is_err());
    assert!(SnapshotSecretPolicy::default().authorize(false).is_ok());
    assert!(SnapshotSecretPolicy::AllowEncrypted.authorize(true).is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn verified_decryption_returns_a_sealed_anonymous_file_only() {
    use std::io::{Read, Write};
    let data = b"private memory contents";
    let encrypted = ciphertext(data);
    let digest = hex::encode(Sha256::digest(data));
    let mut file = super::decrypt(
        encrypted.as_slice(),
        &SnapshotKey::fixture([19; 32]),
        &context(),
        data.len() as u64,
        &digest,
    )
    .unwrap();
    let mut observed = Vec::new();
    file.read_to_end(&mut observed).unwrap();
    assert_eq!(observed, data);
    assert!(file.write_all(b"replacement").is_err());
    assert!(file.set_len(0).is_err());
    assert!(
        super::decrypt(
            encrypted.as_slice(),
            &SnapshotKey::fixture([19; 32]),
            &context(),
            data.len() as u64,
            &"0".repeat(64)
        )
        .is_err()
    );
}
