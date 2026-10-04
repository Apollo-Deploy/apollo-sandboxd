# Runtime artifact and process identity contract

`src/runtime` verifies Firecracker and jailer as root-owned, non-writable,
architecture-correct ELF files, checks their pinned SHA-256 digests and exact
version output, and retains the verified descriptors in `VerifiedRuntime`.
Callers must retain that value for the session. Before an external execution
effect, the artifact is revalidated through its open descriptor; a pathname is
never used as the authority for an already verified artifact.

On Linux, `ProcessIdentity::capture` reads one complete process record, opens a
pidfd, then reads the complete record again and requires the two observations
to match. It records the host boot ID, `/proc/<pid>/stat` start time, real,
effective, saved-set and filesystem UID/GID tuples, executable device/inode and
streamed SHA-256 digest, and a digest of the process cgroup record. `verify`
rereads all of those fields. Signals are sent through the retained pidfd only
after verification, so a recycled PID cannot be signaled or treated as the
managed VMM.

The pidfd is a live kernel handle and is not durable across a daemon restart or
host reboot. Durable session recovery uses `reopen_verified`: it discovers a
candidate PID, verifies the persisted full record, opens a fresh pidfd, and
verifies the record again before adopting it. A different boot ID or any
identity mismatch is a fail-closed recovery result. This module does not claim
that a pidfd survives restart, that `/proc` is available on non-Linux hosts, or
that a trusted host root adversary is contained.

The current process contract is intentionally narrower than full jailer
ownership: it does not yet prove the Firecracker jail directory, API socket,
cgroup inode, or jailer parent-child relationship. The future session launcher
must persist and verify those additional ownership identities before orphan
cleanup.
