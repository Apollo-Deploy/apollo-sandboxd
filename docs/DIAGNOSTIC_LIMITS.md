# VMM diagnostic storage limits

Every new jailed VMM receives a finite Linux `RLIMIT_FSIZE` and a 1024-file
descriptor ceiling through jailer. The file-size ceiling is the larger of
configured guest memory and fixed writable disk capacity. Firecracker uses
files for guest-memory backing and block writes, so those extents must remain
permitted. Diagnostic files have the same hard per-file ceiling; they cannot
grow indefinitely when a guest floods the serial device. Exceeding the ceiling
can terminate the VMM through `SIGXFSZ` or produce a device error. This is a
session failure, detected by process supervision, rather than permission to
discard customer output. Customer stdout/stderr use vsock and the separate
bounded execution journal.

Launch reserves the worst-case size of both diagnostic files in the serialized
state store before creating `jailer.stderr`. The aggregate ceiling is
`max_active_sandboxes × 2 × max(max_memory_mib, max_state_disk_mib)`, converted
to bytes. Each session reserves twice its actual per-file `RLIMIT_FSIZE`; an
immediate SQLite transaction prevents concurrent launches from exceeding that
ceiling. A reservation remains durable through prelaunch and live recovery, and
is released only after identity-checked cleanup proves both diagnostic files
absent.

Before session recovery, startup reconciles missing reservations from durable
sandbox resources and scans the diagnostics tree. Unreserved files, unexpected
file types or owners, links, or files exceeding their reservation fail startup
closed. On `ENOSPC`, diagnostic writes cannot grow past their reserved file
limits; the VMM may report an I/O error or exit. The reservation remains held
until normal cleanup proves the files are gone, so a cleanup failure reduces
admission capacity rather than allowing another session to consume the space.
The aggregate ceiling is a configured logical bound; unrelated host writes can
still exhaust the filesystem. Existing sessions launched before per-file
resource enforcement must be cold-started to acquire those kernel limits.

The implementation follows the pinned
[Firecracker 1.17 jailer resource-limit interface](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/docs/jailer.md)
and [production resource guidance](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/docs/prod-host-setup.md).
