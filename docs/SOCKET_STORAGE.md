# API socket storage and recovery contract

The socket parent belongs to the daemon's trusted filesystem identity. Its
ancestors are opened descriptor by descriptor with no symlink following. Group
and world write access to the parent is rejected. The private staging directory
is owned by the daemon UID and mode 0700. Do not run unrelated or untrusted host
processes under that service UID. Host root is trusted: an API policy cannot
contain a host-root process that already has authority over the daemon and its
files. Guest root receives a separate jailer UID and no host directory authority.

A non-root daemon requires an explicit client UID allowlist that excludes its
own UID. Startup and doctor validate that rule; peer admission also denies its
own UID. GID-only client authorization is therefore available to a root daemon,
not a non-root daemon with a shared filesystem identity. This validation prevents
an authorized untrusted client from sharing the service's filesystem credentials;
it does not defend against compromise of trusted root or the daemon account.

The parent filesystem must support directory user xattrs, directory fsync, and
rename without replacing an existing destination. Startup has no fallback for
missing support. Doctor checks ownership, read-only mount status and a read-only
xattr probe. That probe cannot promise writable xattr capacity, free disk space,
or device durability. Startup must successfully write and sync the actual bounded
ownership record before binding, then persist the socket inode before publishing.
Any failure prevents READY. Reference filesystem checks use ext4 and tmpfs on the
qualified Linux host; other filesystems require the same qualification before use.

One private `.sandboxd-socket-stage` directory holds an atomic ownership xattr and
at most one temporary endpoint. Its versioned CBOR record includes endpoint name,
directory device/inode and prepared/published socket device/inode. It is bounded
to 4096 bytes. Linux defines xattr access as atomic replacement, avoiding an
in-place manifest truncation window. Atomic replacement is not by itself proof of
power-loss durability. See [xattr(7)](https://man7.org/linux/man-pages/man7/xattr.7.html)
and [fsync(2)](https://man7.org/linux/man-pages/man2/fsync.2.html).

The daemon claims the empty private namespace and fsyncs it and its parent before
binding. An unclaimed populated directory is preserved. After binding, it records
the inode and syncs the namespace, publishes with `RENAME_NOREPLACE`, syncs both
directories, and commits the published record. An existing public endpoint is
never overwritten. See [rename(2)](https://man7.org/linux/man-pages/man2/rename.2.html).
Cleanup requires exact ownership and a refused stale connection; unknown public
inodes, wrong directory/endpoint records and corrupt records fail closed.

An upgrade can adopt the previous `socket-owner.cbor` format only when its exact
socket identity matches. The old file is retained. An old interrupted bind that
never persisted that proof cannot be safely adopted automatically. Unknown objects
remain in place for an operator to investigate with inode and process evidence.
Do not repair this by unlinking names or deleting the ownership record.

Downgrade to a pre-correction daemon after an unclean new-daemon exit is unsupported:
the old reader does not understand the new namespace and must refuse its endpoint.
Use forward recovery with the corrected daemon. A clean stop removes the owned
endpoint, but that alone does not establish whole-product state/protocol rollback
compatibility. Rolling daemon/VM upgrades remain a separate release requirement.

Native SIGKILL tests cover namespace creation, durable claim, bind, prepared
identity, rename and publication. Their pre-fix negative control fails at bind.
They do not simulate a power cut or dishonest storage flushes. Whole-product host
reboot, disk-full, rolling upgrade and live-VM recovery qualification remains
required before production completion.
