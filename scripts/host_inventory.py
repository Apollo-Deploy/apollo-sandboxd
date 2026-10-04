#!/usr/bin/env python3
"""Read-only authorized host inventory. No VM, install, reboot, or stress test."""
import subprocess
import sys
if len(sys.argv) != 2:
    raise SystemExit("usage: host_inventory.py SSH_ALIAS")
script = """set +e
uname -a
cat /etc/os-release
systemd-detect-virt
getconf _NPROCESSORS_ONLN
LC_ALL=C lscpu | sed -n '/^Architecture:/p;/^Model name:/p;/^Virtualization:/p;/^Hypervisor vendor:/p'
stat -c '%F %U %G %a' /dev/kvm
id
if test -r /dev/kvm && test -w /dev/kvm; then echo KVM_RW_AVAILABLE; else echo KVM_RW_UNAVAILABLE; fi
stat -fc '%T' /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
free -h
df -h /
for artifact in firecracker jailer; do
    if command -v "$artifact"; then :; else echo "$artifact NOT_FOUND_ON_PATH"; fi
done
exit 0
"""
command = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", sys.argv[1], script]
print("Exact read-only argv:", repr(command), flush=True)
raise SystemExit(subprocess.run(command).returncode)
