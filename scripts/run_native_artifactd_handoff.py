#!/usr/bin/env python3
"""Provision an isolated Artifactd producer and run the public sandboxd handoff test."""
import base64
import hashlib
import io
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path


SERVICE_UID = 424242
SERVICE_GID = 424242
PRODUCER_UID = 424243
RUNTIME_UID = 0
RUNTIME_GID = 0
ARCHITECTURES = {"x86_64": "amd64", "aarch64": "arm64"}
ARTIFACTD_SHA256 = {
    "x86_64": "f90c45c6af42df402749b883526f9f557236cd763815b5ea025255dbc2c1eff5",
    "aarch64": "d77221b8ffb4f3fad0d41062d7c909e4e3b6e1fbb5dd682759d929799c14988a",
}
ARTIFACTD_BIN = {
    "x86_64": "/home/tihan/artifactd-qualification-20261004/target/release/apollo-artifactd",
    "aarch64": "/home/apollo-admin/artifactd-qualification-20261004/target/release/apollo-artifactd",
}
ARTIFACTCTL_BIN = {
    "x86_64": "/home/tihan/artifactd-qualification-20261004/target/release/apollo-artifactctl",
    "aarch64": "/home/apollo-admin/artifactd-qualification-20261004/target/release/apollo-artifactctl",
}
FORMATTER = {
    "x86_64": ("/opt/apollo-lab/sandboxd-pid-limit/tools/mke2fs",
                "14d64b707e37214aff4568470bb4d908232370684c7eff05465d78116c2c9c67"),
    "aarch64": ("/opt/apollo-sandboxd/storage-tools/84419f91298e173cf1569b3a9c957c9f3e26a28852a6025800ed9e0cd9227ea2/mke2fs",
                "84419f91298e173cf1569b3a9c957c9f3e26a28852a6025800ed9e0cd9227ea2"),
}
BASE_CONFIG = {
    "x86_64": "qualification/native-x86-pid-limit/sandboxd.toml",
    "aarch64": "qualification/native-arm64/sandboxd.toml",
}


def run(argv, *, check=True, capture=True, timeout=120, env=None):
    result = subprocess.run(argv, text=True, capture_output=capture, timeout=timeout, env=env)
    if check and result.returncode:
        raise RuntimeError("command failed (%d): %r\n%s" %
                           (result.returncode, argv,
                            (result.stdout + result.stderr)[-3000:] if capture else ""))
    return result


def identity_command(uid, gid, argv):
    drop = (
        "import os,sys; os.setgroups([int(sys.argv[2])]); "
        "os.setgid(int(sys.argv[2])); os.setuid(int(sys.argv[1])); "
        "os.execvp(sys.argv[3], sys.argv[3:])"
    )
    return ["python3", "-c", drop, str(uid), str(gid), *argv]


def assert_identity_available(uid, gid):
    if uid in (0, os.getuid()) or gid in (0, os.getgid()):
        raise RuntimeError("fixture identity conflicts with the runner")
    if run(["getent", "passwd", str(uid)], check=False).stdout:
        raise RuntimeError("fixture UID is already assigned")
    if run(["getent", "group", str(gid)], check=False).stdout:
        raise RuntimeError("fixture GID is already assigned")
    active = run(["ps", "-eo", "uid="], check=True).stdout.split()
    if str(uid) in active:
        raise RuntimeError("fixture UID is already active")


def sha256(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def layer_bytes():
    payload = b"artifactd handoff qualification\n"
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        info = tarfile.TarInfo("proof.txt")
        info.size = len(payload)
        info.mode = 0o444
        info.uid = info.gid = 0
        archive.addfile(info, io.BytesIO(payload))
    return stream.getvalue()


def write_oci_archive(path, architecture):
    layer = layer_bytes()
    layer_digest = "sha256:" + hashlib.sha256(layer).hexdigest()
    config = json.dumps({
        "architecture": architecture,
        "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": [layer_digest]},
    }, sort_keys=True, separators=(",", ":")).encode()
    config_digest = "sha256:" + hashlib.sha256(config).hexdigest()
    manifest = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": config_digest, "size": len(config)},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": layer_digest, "size": len(layer)}],
    }, sort_keys=True, separators=(",", ":")).encode()
    manifest_digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
    index = json.dumps({
        "schemaVersion": 2,
        "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json",
                       "digest": manifest_digest, "size": len(manifest),
                       "platform": {"os": "linux", "architecture": architecture}}],
    }, sort_keys=True, separators=(",", ":")).encode()
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in [
            ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'),
            ("index.json", index),
            ("blobs/sha256/" + config_digest[7:], config),
            ("blobs/sha256/" + manifest_digest[7:], manifest),
            ("blobs/sha256/" + layer_digest[7:], layer),
        ]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o444
            info.uid = info.gid = 0
            archive.addfile(info, io.BytesIO(data))
    os.chmod(path, 0o644)
    return manifest_digest


def action(cli, socket, action, *, input_path=None, peer=None):
    argv = [cli, "--socket", socket, "--server-uid", str(SERVICE_UID),
            "--action", json.dumps(action, separators=(",", ":"))]
    if input_path is not None:
        argv += ["--input", input_path]
    if peer is not None:
        argv = identity_command(peer[0], peer[1], argv)
    result = run(argv)
    return json.loads(result.stdout)


def result(response):
    if not isinstance(response, dict) or response.get("version") != 3:
        raise RuntimeError("unexpected Artifactd response")
    if "Err" in response.get("result", {}):
        raise RuntimeError("Artifactd rejected qualification action")
    value = response.get("result", {}).get("Ok")
    if not isinstance(value, dict):
        raise RuntimeError("Artifactd response omitted result")
    return value


def update_config(base, state, architecture, socket, authority, bootstrap_digest):
    text = Path(base).read_text()
    replacements = {
        'socket = "/run/apollo-lab/sandboxd-pid-limit.sock"':
            'socket = "%s/sandbox-runtime/sandboxd.sock"' % state,
        'socket = "/run/apollo-sandboxd/sandboxd.sock"':
            'socket = "%s/sandbox-runtime/sandboxd.sock"' % state,
        'socket = "/run/apollo-sandboxd-native-arm64/sandboxd.sock"':
            'socket = "%s/sandbox-runtime/sandboxd.sock"' % state,
        'directory = "/var/lib/apollo-lab/sandboxd-pid-limit/daemon-state"':
            'directory = "%s/sandbox-state"' % state,
        'directory = "/var/lib/apollo-sandboxd"':
            'directory = "%s/sandbox-state"' % state,
        'directory = "/var/lib/apollo-sandboxd/native-arm64/state"':
            'directory = "%s/sandbox-state"' % state,
        'drive_directory = "/var/lib/apollo-lab/sandboxd-pid-limit/drives"':
            'drive_directory = "%s/drives"' % state,
        'drive_directory = "/var/lib/apollo-sandboxd/drives"':
            'drive_directory = "%s/drives"' % state,
        'drive_directory = "/var/lib/apollo-sandboxd/native-arm64/drives"':
            'drive_directory = "%s/drives"' % state,
    }
    for original, replacement in replacements.items():
        text = text.replace(original, replacement)
    if architecture == "x86_64":
        text = text.replace('operator_root = "/x"', 'operator_root = "%s"' % authority)
        text = text.replace(
            'images = [{digest = "sha256:5c17339e56d2daf81f38da4693c19b8c9146f6c941066aa6f6835f9a51b34b56", architecture = "x86_64", path = "/opt/apollo-lab/sandboxd-pid-limit/rootfs/x86_64/ubuntu-24.04/rootfs.ext4"}]',
            'images = [{digest = "%s", architecture = "%s", path = "%s/bootstrap-rootfs.ext4"}]'
            % (bootstrap_digest, architecture, state),
        )
    else:
        text = text.replace('operator_root = "/a64"', 'operator_root = "%s"' % authority)
        text = re.sub(
            r"(?ms)^\[\[execution\.images\]\]\n(?:^(?:digest|architecture|path) = .*\n){3}",
            '[[execution.images]]\ndigest = "%s"\narchitecture = "%s"\npath = "%s/bootstrap-rootfs.ext4"\n'
            % (bootstrap_digest, architecture, state),
            text,
            count=1,
        )
    text += ('\n[execution.artifactd]\nprepared_root = "%s/prepared-images"\n'
             'prepared_size_mib = 64\nsocket = "%s"\nserver_uid = %d\n'
             % (state, socket, SERVICE_UID))
    if bootstrap_digest not in text or str(Path(state) / "bootstrap-rootfs.ext4") not in text:
        raise RuntimeError("could not replace the unused base-image catalog entry")
    return text


def main():
    architecture = platform.machine()
    if architecture not in ARCHITECTURES:
        raise SystemExit("native x86_64 or aarch64 Linux required")
    if os.name != "posix" or os.geteuid() != 0:
        raise SystemExit("run this qualification helper as root")
    assert_identity_available(SERVICE_UID, SERVICE_GID)
    assert_identity_available(PRODUCER_UID, SERVICE_GID)
    # Firecracker imposes a short limit on Unix socket paths under operator_root.
    # Keep this root compact; the rest of the fixture stays beneath it.
    state = Path(tempfile.mkdtemp(prefix="adh-", dir="/var/tmp"))
    state.chmod(0o711)
    authority = None
    mount_anchor = None
    anchor_mounted = False
    service = None
    service_wrapper = None
    service_log = tempfile.TemporaryFile()
    try:
        for name in ("artifactd-store", "artifactd-runtime", "producer-state",
                     "sandbox-runtime", "sandbox-state", "drives", "prepared-images"):
            (state / name).mkdir(mode=0o700)
        # The sandbox config bounds the longest Firecracker socket path to 107
        # bytes, leaving room for only a one-character operator root.
        for letter in secrets.SystemRandom().sample("bcdefghjkmnpqrstuvwxyz", 20):
            candidate = Path("/" + letter)
            try:
                candidate.mkdir(mode=0o700)
                authority = candidate
                break
            except FileExistsError:
                continue
        if authority is None:
            raise RuntimeError("no free short operator root is available")
        # Production requires a dedicated private mount at this exact anchor;
        # merely creating the directory would fail the daemon's mount check.
        mount_anchor = authority / "firecracker"
        mount_anchor.mkdir(mode=0o700)
        run(["mount", "--bind", str(mount_anchor), str(mount_anchor)])
        anchor_mounted = True
        run(["mount", "--make-private", str(mount_anchor)])
        run(["chown", "%d:%d" % (SERVICE_UID, SERVICE_GID), str(state / "artifactd-store"),
             str(state / "artifactd-runtime")])
        run(["chmod", "700", str(state / "artifactd-store")])
        run(["chown", "%d:%d" % (PRODUCER_UID, SERVICE_GID), str(state / "producer-state")])
        run(["chmod", "700", str(state / "producer-state")])
        run(["chmod", "700", str(state / "sandbox-runtime"), str(state / "sandbox-state"),
             str(state / "drives"), str(state / "prepared-images")])
        runtime = state / "artifactd-runtime"
        run(["chown", "%d:%d" % (SERVICE_UID, SERVICE_GID), str(runtime)])
        run(["chmod", "710", str(runtime)])
        socket = str(runtime / "artifactd.sock")
        policy = state / "artifactd-policy.json"
        policy.write_text(json.dumps({
            "socket_gid": SERVICE_GID,
            "peers": [
                {"uid": SERVICE_UID, "gid": SERVICE_GID, "role": "admin"},
                {"uid": PRODUCER_UID, "gid": SERVICE_GID, "role": "producer"},
                {"uid": RUNTIME_UID, "gid": RUNTIME_GID, "role": "consumer"},
            ],
        }, separators=(",", ":")))
        policy.chmod(0o600)
        run(["chown", "%d:%d" % (SERVICE_UID, SERVICE_GID), str(policy)])
        artifactd = state / "apollo-artifactd"
        artifactctl = state / "apollo-artifactctl"
        shutil.copyfile(ARTIFACTD_BIN[architecture], artifactd)
        shutil.copyfile(ARTIFACTCTL_BIN[architecture], artifactctl)
        artifactd.chmod(0o755)
        artifactctl.chmod(0o755)
        if sha256(artifactd) != ARTIFACTD_SHA256[architecture]:
            raise RuntimeError("staged Artifactd binary hash mismatch")
        service_wrapper = subprocess.Popen(identity_command(
            SERVICE_UID, SERVICE_GID,
            [str(artifactd), "--store", str(state / "artifactd-store"),
             "--socket", socket, "--policy", str(policy)],
        ), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=service_log)
        ready = False
        deadline = time.monotonic() + 20
        status_action = {"operation": "STATUS"}
        while time.monotonic() < deadline:
            if service_wrapper.poll() is not None:
                service_log.seek(0, os.SEEK_END)
                end = service_log.tell()
                service_log.seek(max(0, end - 8192))
                detail = service_log.read(8192).decode(errors="replace")
                raise RuntimeError("isolated Artifactd exited before readiness: " + detail)
            try:
                action(artifactctl, socket, status_action, peer=(SERVICE_UID, SERVICE_GID))
                ready = True
                break
            except (OSError, RuntimeError, subprocess.CalledProcessError):
                time.sleep(0.1)
        if not ready:
            raise RuntimeError("isolated Artifactd did not become ready")

        oci_archive = state / "input.oci.tar"
        manifest = write_oci_archive(oci_archive, ARCHITECTURES[architecture])
        pin = "sandbox-handoff-%d" % os.getpid()
        imported = result(action(artifactctl, socket, {
            "operation": "IMPORT_OCI_ARCHIVE",
            "platform": {"os": "linux", "architecture": ARCHITECTURES[architecture], "variant": None},
            "pin": pin,
        }, input_path=str(oci_archive), peer=(PRODUCER_UID, SERVICE_GID)))
        if imported.get("manifest_digest") != manifest:
            raise RuntimeError("Artifactd imported a different manifest")
        digest = manifest
        leases = []
        for grantee in ((RUNTIME_UID, RUNTIME_GID), (PRODUCER_UID, SERVICE_GID)):
            response = result(action(artifactctl, socket, {
                "operation": "LEASE_CREATE", "digest": digest,
                "grantee": {"uid": grantee[0], "gid": grantee[1]},
            }, peer=(PRODUCER_UID, SERVICE_GID)))
            leases.append(response["lease_id"])
        prepared = result(action(artifactctl, socket, {
            "operation": "PREPARE", "digest": digest,
            "platform": {"os": "linux", "architecture": ARCHITECTURES[architecture], "variant": None},
        }, peer=(PRODUCER_UID, SERVICE_GID)))
        facts = {
            "prepared_artifact_id": prepared["prepared_artifact_id"],
            "manifest_digest": digest,
            "consumer_lease_id": leases[0],
            "producer_lease_id": leases[1],
            "architecture": "x86_64" if architecture == "x86_64" else "aarch64",
            "producer_uid": PRODUCER_UID,
            "producer_gid": SERVICE_GID,
        }
        encoded = base64.b64encode(json.dumps(facts, separators=(",", ":")).encode()).decode()
        producer_facts = state / "producer-state" / "handoff.json"
        writer = ("import base64,os; p=%r; b=base64.b64decode(%r); "
                  "f=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); "
                  "os.write(f,b); os.fsync(f); os.close(f); "
                  "d=os.open(os.path.dirname(p),os.O_RDONLY|os.O_DIRECTORY); os.fsync(d); os.close(d)"
                  % (str(producer_facts), encoded))
        run(identity_command(PRODUCER_UID, SERVICE_GID, ["python3", "-c", writer]))

        bootstrap_root = state / "empty-root"
        bootstrap_root.mkdir(mode=0o700)
        bootstrap_image = state / "bootstrap-rootfs.ext4"
        run([FORMATTER[architecture][0], "-t", "ext4", "-F", "-d",
             str(bootstrap_root), str(bootstrap_image), "64M"], timeout=120)
        bootstrap_image.chmod(0o444)
        bootstrap_digest = "sha256:" + sha256(bootstrap_image)
        config = update_config(BASE_CONFIG[architecture], str(state), architecture, socket,
                               str(authority), bootstrap_digest)
        config_path = state / "sandboxd.toml"
        config_path.write_text(config)
        config_path.chmod(0o600)
        evidence = state / "sandbox-handoff-evidence.log"
        target_dir = Path.cwd().parent / "target"
        env = dict(os.environ)
        env.update({
            "APOLLO_NATIVE_DAEMON_BIN": str(target_dir / "debug/apollo-sandboxd"),
            "APOLLO_NATIVE_API_CONFIG": str(config_path),
            "APOLLO_NATIVE_API_SOCKET": str(state / "sandbox-runtime/sandboxd.sock"),
            "APOLLO_NATIVE_API_EVIDENCE": str(evidence),
            "APOLLO_NATIVE_ARTIFACTD_SOCKET": socket,
            "APOLLO_NATIVE_ARTIFACTD_UID": str(SERVICE_UID),
            "APOLLO_NATIVE_ARTIFACTD_HANDOFF_FACTS": str(producer_facts),
        })
        native_home = "/home/tihan" if architecture == "x86_64" else "/home/apollo-admin"
        env.update({
            "HOME": native_home,
            "CARGO_HOME": native_home + "/.cargo",
            "RUSTUP_HOME": native_home + "/.rustup",
            "RUSTUP_TOOLCHAIN": "1.96.0" if architecture == "x86_64" else "stable",
            "PATH": "/usr/bin:/bin:" + native_home + "/.cargo/bin",
            "CARGO_TARGET_DIR": str(target_dir),
            "CARGO_BUILD_JOBS": "2",
        })
        cargo = native_home + "/.cargo/bin/cargo"
        if not os.path.isfile(cargo):
            raise RuntimeError("native Rust toolchain cargo is unavailable")
        run([cargo, "build", "--locked", "--bin", "apollo-sandboxd"], timeout=600, env=env)
        try:
            test = run([cargo, "test", "--locked", "--test", "native_artifactd_handoff",
                        "--", "--ignored", "--exact",
                        "native_artifactd_handoff_persists_replays_and_releases_lease", "--nocapture"],
                       timeout=600, env=env)
        except RuntimeError as error:
            daemon_log = evidence.with_suffix(".daemon.log")
            log_tail = (daemon_log.read_text(errors="replace")[-8192:]
                        if daemon_log.exists() else "")
            raise RuntimeError("%s\nprivate daemon stderr tail:\n%s" %
                               (error, log_tail)) from error
        print(test.stdout[-8000:])
        if test.stderr:
            print(test.stderr[-2000:])
        print(json.dumps({"fixture": str(state), "architecture": architecture,
                          "prepared_artifact_id": facts["prepared_artifact_id"],
                          "manifest_digest": digest, "producer_uid": PRODUCER_UID,
                          "consumer_uid": RUNTIME_UID,
                          "sandboxd_evidence": evidence.read_text(),
                          "cleanup": "pending"}))
    finally:
        if service_wrapper is not None:
            if service_wrapper.poll() is None:
                service_wrapper.terminate()
                try:
                    service_wrapper.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    service_wrapper.kill()
                    service_wrapper.wait()
        if anchor_mounted and mount_anchor is not None:
            run(["umount", str(mount_anchor)], check=False)
        shutil.rmtree(state)
        if authority is not None:
            shutil.rmtree(authority)
        service_log.close()
        print(json.dumps({"isolated_fixture_removed": not state.exists()}))


if __name__ == "__main__":
    main()
