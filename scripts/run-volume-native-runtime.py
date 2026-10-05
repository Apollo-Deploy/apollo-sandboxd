#!/usr/bin/env python3
"""Run owner-built, matching-source volume lifecycle binaries in a fresh fixture.

Invoke under sudo in a private mount namespace. This script runs no compilers
and retains the fixture, hashes, configuration, and logs on success or failure.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import select
import signal
import subprocess
import tempfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stop_fixture_daemons(executable: Path, config: Path):
    stopped = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            descriptor = os.pidfd_open(int(proc.name))
        except ProcessLookupError:
            continue
        try:
            try:
                actual = Path(os.readlink(proc / 'exe'))
                arguments = (proc / 'cmdline').read_bytes().split(b'\0')
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
            if actual != executable or str(config).encode() not in arguments:
                continue
            # The pidfd pins the observed process; no PID-reuse signal race.
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            ready = select.poll()
            ready.register(descriptor, select.POLLIN)
            if not ready.poll(5000):
                raise RuntimeError('fixture daemon death was not confirmed')
            stopped.append(int(proc.name))
        finally:
            os.close(descriptor)
    return stopped


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--daemon', type=Path, required=True)
    parser.add_argument('--test-binary', type=Path, required=True)
    parser.add_argument('--initramfs', type=Path, required=True)
    parser.add_argument('--source-manifest', type=Path, required=True)
    args = parser.parse_args()
    owner = int(os.environ.get('SUDO_UID', '-1'))
    if os.geteuid() != 0 or owner <= 0 or platform.system() != 'Linux':
        raise SystemExit('runtime fixture requires sudo from a non-root build owner')
    architecture = platform.machine()
    if architecture not in ('aarch64', 'x86_64'):
        raise SystemExit('native supported architecture required')
    inputs = (args.daemon, args.test_binary, args.initramfs, args.source_manifest)
    for path in inputs:
        if path.is_symlink() or not path.is_file() or path.stat().st_uid != owner:
            raise SystemExit('qualification input must be a regular build-owner file')
    root = Path(tempfile.mkdtemp(prefix='sandboxd-volume-native-', dir='/var/tmp'))
    root.chmod(0o700)
    binaries = root / 'binaries'; binaries.mkdir(mode=0o700)
    copied = {}
    for path in inputs:
        target = binaries / path.name
        expected = digest(path)
        shutil.copyfile(path, target)
        target.chmod(0o444 if path in (args.initramfs, args.source_manifest) else 0o555)
        if digest(target) != expected:
            raise SystemExit('qualification input changed during copy')
        copied[path.name] = {'sha256': expected, 'path': str(target)}
    for name in ('state', 'drives', 'socket'):
        (root / name).mkdir(mode=0o700)
    anchor = None
    for letter in 'vwxyzbcdefghjkmnpqrstu':
        candidate = Path('/' + letter)
        try:
            candidate.mkdir(mode=0o700); anchor = candidate; break
        except FileExistsError:
            pass
    if anchor is None:
        raise SystemExit('no short private jail anchor available')
    firecracker = anchor / 'firecracker'; firecracker.mkdir(mode=0o700)
    subprocess.run(['mount', '--bind', str(firecracker), str(firecracker)], check=True)
    subprocess.run(['mount', '--make-private', str(firecracker)], check=True)
    template = Path(__file__).resolve().parents[1] / 'qualification' / ('native-arm64' if architecture == 'aarch64' else 'native-x86-pid-limit') / 'sandboxd.toml'
    text = template.read_text()
    def replace(key, value):
        nonlocal text
        text, count = re.subn(r'(?m)^' + re.escape(key) + r' = .+$', key + ' = ' + value, text)
        if count != 1:
            raise RuntimeError('fixture config requires one ' + key)
    replace('socket', json.dumps(str(root / 'socket/sandboxd.sock')))
    replace('directory', json.dumps(str(root / 'state')))
    replace('drive_directory', json.dumps(str(root / 'drives')))
    replace('operator_root', json.dumps(str(anchor)))
    replace('initramfs', json.dumps(copied[args.initramfs.name]['path']))
    replace('initramfs_sha256', json.dumps(copied[args.initramfs.name]['sha256']))
    # Fresh ranges avoid reusing the baseline fixture's VMM identities or CID.
    slot = int.from_bytes(os.urandom(2), 'little') * 16
    for key, value in [('uid_first', 600000 + slot), ('uid_last', 600015 + slot),
                       ('gid_first', 600000 + slot), ('gid_last', 600015 + slot),
                       ('cid_first', 20000 + slot), ('cid_last', 20015 + slot)]:
        replace(key, str(value))
    config = root / 'sandboxd.toml'; config.write_text(text); config.chmod(0o600)
    import tomllib
    admitted = tomllib.loads(text)
    evidence = root / 'evidence.log'
    env = dict(os.environ,
               APOLLO_NATIVE_API_CONFIG=str(config),
               APOLLO_NATIVE_API_SOCKET=admitted['daemon']['socket'],
               APOLLO_NATIVE_API_EVIDENCE=str(evidence),
               APOLLO_NATIVE_DAEMON_BIN=copied[args.daemon.name]['path'],
               APOLLO_NATIVE_DAEMON_SHA256=copied[args.daemon.name]['sha256'],
               APOLLO_NATIVE_SOURCE_REVISION=copied[args.source_manifest.name]['sha256'],
               APOLLO_NATIVE_BASE_DIGEST=admitted['execution']['images'][0]['digest'].removeprefix('sha256:'),
               APOLLO_NATIVE_RUNTIME_PROFILE=admitted['runtimes'][0]['name'],
               APOLLO_NATIVE_KERNEL_PROFILE=admitted['kernels'][0]['name'],
               APOLLO_NATIVE_VOLUME_QUALIFY='1')
    env.pop('APOLLO_NATIVE_SNAPSHOT_QUALIFY', None)
    command = [copied[args.test_binary.name]['path'], '--ignored', '--exact',
               'native_public_api_lifecycle_and_daemon_restart', '--nocapture']
    receipt = {'architecture': architecture, 'build_owner_uid': owner,
               'fixture': str(root), 'operator_root': str(anchor),
               'inputs': copied, 'config_sha256': digest(config), 'command': command}
    (root / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    with (root / 'test.log').open('w') as output:
        try:
            result = subprocess.run(command, env=env, stdout=output, stderr=subprocess.STDOUT, timeout=480)
            code = result.returncode
        except subprocess.TimeoutExpired:
            code = 124
            receipt['timeout'] = True
    receipt['fixture_daemons_stopped'] = stop_fixture_daemons(
        Path(copied[args.daemon.name]['path']), config)
    receipt['exit'] = code
    receipt['evidence'] = evidence.read_text() if evidence.exists() else ''
    for name in ('test.log', 'evidence.daemon.log'):
        path = root / name
        if path.exists():
            receipt[name] = path.read_text(errors='replace')[-32768:]
    (root / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt), flush=True)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
