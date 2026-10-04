# systemd installation and privilege boundary

The supplied unit is an explicit, unqualified deployment candidate. Its
syntax, restart behavior and capability/device bounds must be exercised with
the installed runtime and kernel catalogs before a production installation.
The native test harness currently launches the daemon directly; that evidence
does not prove this unit works. Do not automatically enable it during install.

Install the daemon and CLI at `/usr/local/bin`, the unit at
`/etc/systemd/system/apollo-sandboxd.service`, and the root-owned configuration
at `/etc/apollo-sandboxd/config.toml`. Trusted binaries and guest artifacts must
remain root-owned and unwritable by API clients. `config.example.toml` contains
deliberately invalid digests and must be replaced with verified catalogs.

The unit requires systemd 254 or newer, cgroup v2 and controller delegation.
Set `execution.operator_root = "/run/asd"` and
`execution.cgroup_parent = "/sys/fs/cgroup/system.slice/apollo-sandboxd.service"`.
The short runtime root is required by the generated Unix socket path lengths.
Before starting the daemon, provision `/run/asd/firecracker` as a dedicated
mount whose propagation type is private. It must have root ownership and mode
0700. Provision it during trusted host boot, before service mount namespaces or
sandbox sessions exist. The daemon never creates this mount: replacing the
directory with an overmount at runtime could hide descendants visible only in
another mount namespace. Startup and `doctor` therefore fail closed when the
path is not a distinct private mount. Verify it with both
`findmnt -T /run/asd/firecracker -o TARGET,PROPAGATION` and the daemon's
`doctor` command. A self-bind performed during daemon restart is not an
acceptable substitute.

Create the configured drive directory under the durable state directory with
root ownership and mode 0700. Both runtime directories survive daemon stops;
they disappear on host reboot. Writable drives belong in durable storage.

## Privileged exceptions

The current daemon requires root. A dedicated unprivileged service account is
not supported by its launch authority. The capability bounding set permits
mounts/namespaces (`SYS_ADMIN`), chroot (`SYS_CHROOT`), jail ownership and
privilege drop (`CHOWN`, `FOWNER`, `DAC_OVERRIDE`, `SETUID`, `SETGID`), device
node creation (`MKNOD`), owned VMM signals (`KILL`) and resource limits
(`SYS_RESOURCE`). These are service privileges; jailer drops the VMM to its
durably assigned non-root UID/GID. No ambient capabilities are configured.
Firecracker retains its default seccomp filters.

`KillMode=process` preserves running VMMs when the daemon stops. Default
control-group killing would violate restart and rolling-upgrade semantics.
Operators must stop/destroy sandboxes through the public API when intentionally
decommissioning the host. The retained cgroups and runtime directories are
reconciled through durable identity checks, not removed by a unit cleanup hook.
`TasksMax` and `LimitNOFILE` are finite aggregate service limits; set sandbox
quotas below the capacity they provide.

`ProtectSystem`, `ProtectHome`, `PrivateTmp` and `PrivateMounts` are disabled
because they create a private mount namespace. A restarted daemon could then
lose access to bind mounts staged by its predecessor. This is a material
filesystem privilege exception, not a claim of maximal systemd hardening.
The dedicated `/run/asd/firecracker` mount described above is a narrower mount
boundary inside the host namespace; it does not place the daemon itself in a
private namespace.
No general syscall filter is added over jailer: namespace, mount and KVM setup
must remain possible. User namespaces are disabled for the host processes.
Guest namespaces remain inside the VM.

`NoNewPrivileges`, device restrictions and the capability list require native
unit qualification. Device node creation needs `m` as well as access rights.
The TUN device is allowed because jailer creates that node even for a VM with
no NIC; sandboxd still rejects unsupported external attachment execution.

The unit uses `Type=simple`. No watchdog is configured because the daemon has
no `sd_notify` watchdog integration yet. A watchdog configuration without actual
heartbeats would restart healthy daemons and would not establish VM health.

## Validation

Run `systemd-analyze verify packaging/systemd/apollo-sandboxd.service`, then
exercise create/exec/stop, `systemctl restart apollo-sandboxd`, SIGKILL recovery,
and rolling replacement under the actual installed unit. Record source,
binary, catalog and unit digests and prove VMM PIDs survive daemon restart.
Do not count a syntax-only check as production service qualification.

Source references: [Firecracker jailer](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/docs/jailer.md)
and [systemd process termination semantics](https://github.com/systemd/systemd/blob/v257/man/systemd.kill.xml).
