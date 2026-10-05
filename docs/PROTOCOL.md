# Local administrative protocol

The API includes administrative metadata, fenced VM/guest operations, descriptor
output sinks, prepared image handoff, and immutable filesystem export. Individual
capabilities require native qualification; protocol support alone is not release approval.

Frames use a 20-byte header: `ASD\0`, big-endian u16 version (2), zero u16 flags,
big-endian u32 body length, and big-endian u64 request ID. Body encoding is CBOR.
One request and response use one Unix stream connection. Response request ID must
match. Unknown version/flags, empty/oversized frames, trailing CBOR data, tags,
indefinite containers, excessive nesting, or excessive collection counts fail.

The wire ceiling is 1 MiB; daemon request bodies have an additional 128 KiB
ceiling checked before allocation/deserialization. CBOR preflight caps nesting
at 32, each map at 512 pairs, each array at 65,536 entries, and total items at
131,072. File/output payload definitions cap individual chunks at 64 KiB.
Connections have finite configured concurrency (maximum 64). One bounded worker
owns SQLite, with a waiting queue no larger than the connection limit. Queue
saturation returns `QuotaExceeded`. Authentication, accepts, static administrative
responses, and periodic scan submission do not await the SQLite worker.

The configured request deadline (maximum 30 seconds) covers reading and waiting
for dispatch/result. Writing the result has a separate one-second bound. Expired
or disconnected requests not yet dispatched are skipped. A started transaction
may commit after the caller receives `RequestTimeout` or disconnects: timeout is
an uncertain result, and the caller must replay the identical operation/body to
resolve it. A saved receipt is read before current catalog admission, so removing
a profile cannot invalidate a committed retry. These are metadata semantics;
no claim is made about canceling unimplemented guest execution.

Graceful shutdown stops accepting, aborts client I/O, closes the state queue, and
joins the SQLite owner. Already-started transactions finish or fail; queued jobs
whose clients disappeared are skipped. No hard overall drain deadline is claimed.
SQLite lock contention has a five-second busy timeout, but filesystem latency is
not a hard bounded host guarantee. Native crash/restart qualification is absent.
Count/byte ceilings are allocation bounds, not measured aggregate RSS guarantees.

Linux SO_PEERCRED authenticates connection-time UID, GID, and PID. Nonempty
configured allowlists are conjunctive; an empty UID and GID policy denies access.
Optional PID constraints apply to the connecting process. An authorized process
can deliberately delegate an already-connected FD; this is not process-bound
per-message authentication. Owner scope is the authenticated UID.

Accepted public mutations and guest operations carry an owner-scoped positive,
contiguous `operation_sequence`. The daemon durably exposes the accepted
watermark through `OperationWatermark`; a replay is checked by operation ID and
digest before sequence admission. A committed operation replay returns its
committed result; a different body is `OperationConflict`; an unseen sequence
below the watermark is `OperationReceiptUnavailable`; a skipped sequence is
`OperationOutOfOrder`. This prevents an old operation ID from becoming a new
mutation after its receipt is reclaimed. Terminal receipts are collected oldest
first at capacity, while guest-pending and session-recovery-linked receipts are
never collected. Invalid/rejected mutations do not advance the watermark.

Destroy requires an active lease and stopped metadata with no session. Recreating
a destroyed identity requires its previous generation and advances generation.
A lease that has been durably recorded expired cannot renew after clock rollback.
An owner may acquire a new finite lease only for stopped expired metadata, fenced
by the previous token and generations; the old token never regains authority.
Wall-clock behavior before expiry is durably observed remains unqualified.

Events use per-owner durable public sequences and separate internal retention IDs.
GAP is the half-open unavailable range `[from_sequence, first_available)`. Complete
eviction still reports a gap. Other owners cannot observe another owner's new
event sequence counts. Schema-1 migration preserves historical global cursors and
uses their high-water mark before private allocation; old cursor numbers remain
historical. State schema 2 rejects unknown newer schemas; old schema-1 binaries
cannot open schema 2. Live daemon upgrade compatibility is not qualified.

Store open and reads compare the duplicated indexed sandbox identity, generation,
lease expiry and lease/session generations with the decoded record, validate its
spec, and reject runtime states unsupported by this administrative store. This
detects the tested semantic inconsistencies; it is not full power-cut or artifact
recovery qualification. Receipt and tombstone reclamation, cumulative WAL growth
and clock discontinuities remain open release blockers. Socket publication now
uses a durably claimed private namespace and prepared inode before public rename.
See [the socket storage contract](SOCKET_STORAGE.md) for required xattrs, identity
separation, migration rules and the distinction between SIGKILL and power-loss
evidence. Unknown socket inodes are preserved; no blind unlink conceals failures.

Guest protocol identities include sandbox/session generations, CID, protocol
version, and a constant-time checked 32-byte boot nonce. Nonce and secret debug
output is redacted and buffers use zeroization. These definitions do not deliver
secrets, establish vsock, or supervise a guest.

## Descriptor image import and filesystem export

Protocol 2 requires an explicit execution `max_processes` policy; version 1
clients fail framing validation instead of receiving silently weaker isolation.
`ImageCommand::ImportPrepared` names an Artifactd prepared artifact, its
manifest digest, producer-issued lease, and target architecture. Sandboxd
persists its operation tokens and handoff phase before contacting Artifactd,
receives a read-only prepared-rootfs directory descriptor, and owns ext4 image
construction and publication. It releases the producer lease only after the
prepared image is durable. Image preparation owns a bounded queue entry after
admission. If the request deadline expires after dispatch, `ImagePending`
identifies the durable operation; replay resumes the handoff without admitting
a new identity. Registry access, archive intake, and OCI layer extraction are
owned by Artifactd and are not sandboxd API operations.

The current source inventory has no production orchestrator invoking
`ImportPrepared`; `scripts/run_native_artifactd_handoff.py` is qualification
orchestration only. The BuildKit publisher publishes through Artifactd, while
Node's artifact application targets its separate MicroSandbox workload path.
Neither is a sandboxd caller. Wiring a real prepared-rootfs producer to this
consumer, including durable ownership and recovery of the producer-issued
lease, remains an open integration gate.

`FilesystemExport` carries an operation sequence, full session fence and byte/entry
bounds. A successful response contains the OCI layer receipt and exactly one
sealed output descriptor; errors and other responses contain no descriptors.
The descriptor-aware client receives rights with the first frame bytes and rejects
wrong descriptor counts. Native crash/restart, resource and guest isolation
qualification remains required for this new export path.

`operation_inspect` is a read-only query with `operation` and
`operation_sequence`; the identity must encode the same positive sequence.
The authenticated service UID selects the receipt partition. Its
`operation_receipt` response includes those fields, `accepted_sequence`,
`state`, `request_digest` and `response`. The optional digest is an opaque
server-normalized SHA-256; it is not a client's semantic request digest.
Inspection reads both operation tables and pending lifecycle links in one
transaction and never admits, replays or transfers descriptors.

States: `pending` retains an unresolved effect or lifecycle link; `complete`
retains the operation response, which may be an error or acknowledgment rather
than successful execution; `unavailable` has no retained receipt at or below the
owner's watermark; `unknown` has no receipt above it. Missing states return null
digest/response and do not authorize retry or intent replacement. A completed
filesystem-export response is metadata only; its original descriptor must be
reacquired through exact replay and independently checked. Duplicate IDs across
operation journals fail closed as a storage error.
