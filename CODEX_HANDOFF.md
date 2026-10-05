# Codex Development Handoff

Prepared 2026-10-04 (Africa/Johannesburg) for migration from local Codex to Codex Cloud. This document preserves session context; source inspection is still required. Historical test results below are explicitly separated from current source facts. No new features were implemented while preparing this handoff.

## 1. Executive Summary

Apollo Sandboxd is a standalone Rust Firecracker sandbox platform: daemon, CLI, public host/guest protocols, Firecracker API client, and trusted guest supervisor. The public repository is **https://github.com/Apollo-Deploy/apollo-sandboxd**, branch `main`, MIT licensed.

The user originally requested a finished production product with extensive native isolation, recovery, storage, and integration qualification. Implementation is substantial, but required qualification and release review remain unfinished. Most recent development added additional-volume wiring and aggregate diagnostic-storage reservations after an independent review found gaps. Those changes were published before a combined full-suite run or independent re-review was completed. Do not infer production readiness from publication.

First focus: establish a reproducible build/test baseline at the published commit, independently inspect the latest volume/diagnostic/cleanup changes, fix reproducible defects, and prepare current-revision native Linux x86_64 evidence. Keep the public repository free of standalone performance reports, verdict documents, internal review reports, and qualification receipts as the user requested. This handoff is an explicitly requested development-context exception; do not create a new public completion report.

## 2. Original Objective

Build one final provider-neutral `apollo-sandboxd` Rust product using mandatory Firecracker+jailer for untrusted Linux execution. It must run without any other Apollo package. It is not a launcher-only helper, MVP, MicroSandbox wrapper, host execution service, or Docker fallback.

The original specification had 156 numbered sections. Raw originals exist only in local ignored files `docs/review/ORIGINAL_PRODUCTION_SPEC.md` and `docs/review/ORIGINAL_REVIEW_SPEC.md`; **they are not available in a GitHub clone**. The requirements summarized here preserve the critical product and release boundaries. Do not assume the full originals are tracked.

Required capabilities: secure microVM lifecycle; custom OCI/raw images; guest-root execution; concurrent execs; PTY; raw streaming stdin/stdout/stderr; detach/reattach; signals/cancel/timeouts; complete guest file APIs and bounded transfers/tree import; immutable base plus mutable state and extra block volumes; filesystem persistence/checkpoints; pause/resume, encrypted full snapshots and suspend/restore; resource limits; external network descriptors/network-none; secrets; finite leases, independent TTL/idle/session/exec lifetimes; metrics/health/events; crash/restart/reboot recovery; rolling daemon and runtime upgrades; image caching/GC; stable CLI/API; systemd/doctor tooling.

Additional original requirements include optional balloon (never a hard isolation boundary), entropy where needed, allowed CPU templates, block/net token-bucket rate limits, nonsecret MMDS, port readiness, trusted artifact version/digest/owner/mode verification, image configuration defaults, safe archive whiteouts/xattrs/hardlinks, quota/backpressure/GC ownership, separate health dimensions, and explicit EVENT_GAP/OUTPUT_GAP. Capability discovery must report supported combinations honestly. Original qualification scale included one VM, 100 sequential, 100 concurrent where resources permit, hundreds/thousands of execs, concurrent transfers and repeated daemon restart. Fuzz/property gates cover host/guest/Firecracker parsers, OCI/layers/tree metadata, state/snapshot/checkpoint/lease/event decoders, generation/idempotency/allocator uniqueness, deterministic manifests and no foreign cleanup.

Production proof must use real Linux/KVM, Firecracker, jailer, guest/rootfs, persistence/snapshot/recovery behavior, malicious guest tests, >20,000 lifecycle churn, measured resources/latencies, and external netd/logd integration. Fixture-only evidence cannot close those requirements.

## 3. Requirements and Constraints

### Hard constraints

- Zero dependencies on other Apollo repositories/packages: agent, logd, netd, control-plane, build/node/telemetry protocols, edge gateway, or domain/database crates. No Apollo Git dependencies or required Apollo processes. Use generic sandbox identities, never tenant/project/deployment/build concepts.
- Supported control plane goes through sandboxd. Orchestrators must not manage its Firecracker processes directly.
- Mandatory verified same-release Firecracker+jailer; default production seccomp; unique durable UID/GID and vsock CID allocations; chroot/namespaces/cgroups/privilege drop. Never use `--no-seccomp`, debug runtimes, PATH-discovered unverified artifacts, arbitrary guest kernels, or isolation fallbacks.
- Guest root, kernel/userspace, OCI content, guest telemetry, client inputs, and output are hostile. Host enforcement never depends on guest cooperation.
- Durable logical sandbox differs from active VM session. Every mutation is generation-fenced and operation-ID idempotent; conflicting operation bodies fail. Persist intent before kernel/runtime effects, observe, then persist result.
- Local bounded versioned Unix-stream API with SO_PEERCRED authorization and hardened socket ownership/cleanup. No internet-facing control API in this package.
- Trusted guest bootstrap is separate from the customer filesystem. Control uses vsock, authenticated session generation/nonce handshake. Snapshot restore invalidates transport; re-handshake/rebind is mandatory.
- Commands are exact argv, shell only when explicitly supplied. Output preserves bytes, stream/sequence metadata, disk-backed bounded journals, explicit GAP. SCM_RIGHTS sinks have Required/BestEffort/Disabled policies.
- Files operate inside guest. Host image/volume resources require trusted catalogs or safe import; cleanup requires ownership evidence, not naming prefixes.
- OCI digest verification for manifest/config/layers, multiarch resolution, correct whiteouts/links/metadata, safe extraction, bounded cache/GC. Tags are not immutable identity.
- Full memory snapshots authenticated/encrypted at rest, manifest/digests/runtime compatibility checked. Default reject snapshots after secret injection unless explicit encrypted secret policy. No plaintext durable secret values.
- None means no NIC. ExternalAttachment uses pre-created netns/TAP and generic descriptors; sandboxd does not create host NAT/firewalls/network policy. Missing attachment fails closed.
- All queues, requests, arrays, transfers, disk artifacts, concurrent operations, and histories bounded. Metrics provenance is HOST_ENFORCED/FIRECRACKER_REPORTED/GUEST_REPORTED.
- Normal Rust modules preferably 100–300 LOC, soft threshold ~350, hard non-generated ceiling 500. Unsafe narrow/documented; workspace denies unsafe by default with scoped exceptions where needed.

### Scope evolution and permanent non-goals

Original architecture support included Linux x86_64 and aarch64 KVM. User explicitly narrowed active work to **x86_64 only for now** because only that host exists. Do not count aarch64 as qualified.

Non-goals: global scheduling, cloud provisioning, billing, central logs/metrics, global network policy/discovery, host TAP/netns creation, authoritative DNS, HTTP/TLS edge routing, distributed storage control plane, GPU, Windows/macOS guests, live migration, supported nested KVM, CNI/Kubernetes/container orchestration, L7 policy. Docker/containerd may run inside a guest profile; never use host Docker to run customer work. Upstream developer-preview diff snapshots are excluded until upstream production support.

## 4. Development Rules

No `AGENTS.md` was found inside this repository in the current inspection. The user supplied rules directly in the session, which must survive migration:

- Search first (`rg`), read only needed lines, avoid rereading unchanged files.
- Narrow tests first; full suite once at the end of a batch. Avoid busy sleep/poll loops; wait within a command where appropriate.
- Preserve dirty/unrelated work. No reset, clean, discard, stash, or mass rewrite to prepare migration.
- After two failed attempts at the same fix, stop the loop and report what was learned/change approach.
- Delegate self-contained investigation, but use small/fast agents. User explicitly stopped all Astra subagents and requested **GPT-6 Luna at max reasoning**. Use Luna max sparingly; no Astra unless user changes this.
- Context7 is permitted if stuck; no Context7-dependent change was needed in the retained work.
- Keep decisions source-grounded, test provenance exact, no invented readiness/performance claims.
- Mandatory independent Red Team Implementation skill subagent release gate, inspect real code/diffs/config/tests/runtime/evidence against original requirements, not document-only threat modeling. Fix/re-review until no blocking findings or accurately report partial/blocked. Primary agent cannot approve itself.
- Skill available locally at `/Users/tihan-nico/.agents/skills/plan-implementation-red-team/SKILL.md`; not tracked and may be absent in Cloud. Discover the equivalent skill, or state its absence honestly. Do not silently mark the gate passed without it.

## 5. Architecture

Workspace `Cargo.toml`: root daemon/CLI plus `crates/sandboxd-protocol`, `crates/guest-protocol`, `crates/firecracker-api`, `guest-agent`; `fuzz` separate/excluded. Rust edition 2024, minimum Rust 1.93; MIT inherited by workspace packages, dependencies pinned in `Cargo.lock`.

Host flow: CLI/client -> bounded framed Unix API/peer credentials -> handlers and serialized state worker -> RuntimeAuthority verified catalogs -> durable session/prelaunch intents -> fixed state drive + descriptor-pinned jail assets -> jailer/cgroup -> Firecracker Unix HTTP configuration -> vsock guest handshake -> authenticated guest configuration -> ready/runtime installation.

Important boundaries:

- `src/api/`: server/client, ancillary FDs, state worker, runtime authority, boot/install/recovery, guest commands, checkpoints/snapshots.
- `src/state/`: SQLite durable identities, generations, operation receipts, leases/events, sessions, launch manifests, state drives, exec metadata, snapshots/checkpoints, allocators, migrations. `src/state/schema.rs` now includes schema version 20 and `diagnostic_reservations`.
- `src/runtime/`, `src/jailer/`, `src/process/`, `src/session/`: trust verification, jail staging, cgroups, strong process identity, boot/pause/restore/cleanup/reconciliation.
- `src/security/`: safe directory/path and ownership operations.
- `src/guest/`, `guest-agent/src/`, `crates/guest-protocol/`: vsock, authenticated identity/rebind, bootstrap, processes/PTY/files, guest metrics/network/volume configuration.
- `src/image/`, `src/storage/`, `src/snapshot/`: Artifactd prepared-FD handoff, sandbox-owned ext4 images, durable state/checkpoints/encrypted snapshots.
- `src/exec/`, `src/events/`, `src/network/`: output journal/sinks, bounded events, generic external attachments.
- `src/volume_catalog.rs`: catalog resolution, inode/size pins, advisory shared/exclusive locks.
- `src/session/diagnostics.rs`, `src/state/diagnostics_quota.rs`: startup diagnostic scan and durable aggregate reservations.
- `packaging/systemd/apollo-sandboxd.service`: deployment candidate, must be exercised natively.

Standalone SQLite is bundled through rusqlite; no external database/broker. Tokio, rustix/nix, serde/CBOR, SHA256, guest filesystem archive/xattr support, and ChaCha20-Poly1305 are focused dependencies. Docs: `docs/PROTOCOL.md`, `docs/SYSTEMD.md`, `docs/RUNTIME_PROCESS_IDENTITY.md`, `docs/SOCKET_STORAGE.md`, `docs/DIAGNOSTIC_LIMITS.md`.

## 6. Important Decisions

**Decision:** keep networking/logging external through descriptors/FDs.  
**Reason:** provider-neutral standalone ownership.  
**Alternatives considered:** importing netd/logd implementations.  
**Why rejected:** forbidden dependency/runtime coupling.  
**Files:** `src/network/`, `src/api/ancillary.rs`, output sink modules, public protocols.

**Decision:** trusted private mount anchor provisioned at host boot.  
**Reason:** a runtime overmount/self-bind can hide descendants visible only in peer mount namespaces and break safe recovery.  
**Alternatives:** daemon creates anchor automatically on restart.  
**Why rejected:** namespace ownership counterexample; daemon must verify/fail closed.  
**Files:** `src/session/asset_mount.rs`, `asset_setup.rs`, `asset_recovery.rs`, `docs/SYSTEMD.md`.

**Decision:** remove identity-matched empty cgroup before jail/assets/socket teardown.  
**Reason:** unexpected remaining members must prevent destructive cleanup rather than cause a late error after resources disappear.  
**Alternatives:** teardown first then check cgroup.  
**Why rejected:** reproducible source counterexample.  
**Files:** `src/session/cleanup.rs`, `reconcile_prelaunch.rs`.

**Decision:** additional volumes use trusted operator catalog/inode pins.  
**Reason:** caller paths must not confer host filesystem authority.  
**Alternatives:** arbitrary paths or blanket reject all volumes.  
**Why rejected:** arbitrary paths unsafe; blanket rejection fails required capability.  
**Files:** `src/config.rs`, `src/volume_catalog.rs`, `src/state/session.rs`, runtime boot/authority, session assets/configure/boot, guest volumes. Current implementation uses regular files, not arbitrary block devices; verify exclusivity across daemon restart.

**Decision:** worst-case diagnostic reservation rather than a novel shared ring.  
**Reason:** reuse serialized durable state and finite existing file limits; make concurrent admission/release testable.  
**Alternatives:** fixed global ring design explored but not implemented.  
**Why rejected:** greater ownership/recovery complexity.  
**Files:** diagnostic modules/schema/journal/recovery/cleanup proofs.

**Decision:** public repo under Apollo-Deploy, MIT, no public performance/verdict/review/receipt documents.  
**Reason:** explicit user publishing request.  
**Alternatives:** prior local Apache license; initial publication under active account nanashili (already changed to MIT).  
**Why rejected:** user corrected organization; transferred and updated remote.  
**Files:** `LICENSE`, workspace license, README, `.gitignore`.

## 7. Work Completed

Repository-verified source exists for the architecture above; this is implementation presence, not complete production proof.

Retained concrete fixes:

1. `src/session/asset_recovery.rs` + `asset_recovery_tests.rs`: crash-progress recovery, six Linux ignored attacks for empty skeleton, root bind before/after mount-ID persistence, placeholder before/after identity persistence, asset bind before ID persistence; private anchor/peer namespace witness preservation. Split tests to keep files <=500.
2. `src/api/runtime_service.rs`: `cleanup_uninstalled_boot` handles post-boot event-router initialization failure with durable runtime-loss/stop cleanup, rather than leaking an uninstalled VM.
3. `src/state/runtime_inventory.rs`: failed start replay replaces linked Start response with terminal RecoveryFailed; retry cannot launch duplicate VM.
4. `src/state/schema.rs`, `tests/support/historical.rs`, `tests/migration_contract.rs`, `tests/session_process_contract.rs`: validate historical v1/v3 schema/integrity before WAL; frozen fixtures; preserve v3 events/cursors; malformed schema does not alter schema/version/journal mode.
5. Native API/boot tests now explicitly ignored unless selected with `--ignored`; scripts were updated. Ordinary suite no longer panics for missing native environment.
6. `cleanup.rs`, `reconcile_prelaunch.rs`: cgroup identity/population/absence barrier before teardown; live-PID fixture preserves jail/socket/stage on rejection.
7. Additional-volume source wiring: configured catalog; durable `VolumePin`; inode/size/policy reopen; `AssetSetup`/assets extended; preboot Firecracker drives/rate limits; authenticated `ConfigureVolumes`; Linux guest mount logic. RuntimeAuthority no longer blanket rejects nonempty volumes. **Needs combined/native verification.**
8. Diagnostic source wiring: reservation hook before jailer stderr creation; immediate SQLite aggregate reservation; startup reconciliation/scanner; cleanup proof includes diagnostic absence; release follows proof. **Needs combined/native verification.**
9. Host cleanup completed historically with zero matching Apollo/Docker paths/processes/units/packages/sockets/cgroups/mounts in audit.
10. Public initial commit `b2af1ed` includes source and MIT publishing changes; transfer to Apollo-Deploy verified public.

## 8. Work in Progress

There are no visible staged/unstaged/untracked changes at handoff start. Nevertheless last implementation batch is unfinished verification-wise:

- Volume code and diagnostic quota landed concurrently. Final local broad checks were not recorded before the user switched to publication.
- Four volume-catalog focused tests passed historically; drive configuration/all-target checks had been requested but final result unavailable.
- Diagnostics quota/scanner focused tests passed before another transient compile change; final rerun result unavailable.
- Fresh independent review of the combined current tree has not happened.
- Current executable-input digest differs from all retained native evidence.
- Published sources include safe-mount/lock/permission/snapshot/recovery behavior that still requires scrutiny; do not assume complete from wiring.

## 9. Conversation Context That Is Not Obvious From Code

- User was frustrated by stopping early and explicitly asked to fix findings, not merely explain partial status.
- SSH alias supplied: `tihan-apollo`, authorized qualification host. Only x86_64 available; no aarch64 blocker should stop x86_64 progress.
- User separately said **cleanup all Apollo and Docker on tihan-apollo**. This was done; old test assets/configuration were removed. Qualification scripts still contain historical paths that no longer exist.
- No dedicated reboot authorization was established in available retained context. Do not reboot the host or run disruptive unrelated-host attacks based only on earlier qualification authorization.
- Publication was an intervening task; user then requested Cloud migration/handoff only. Do not implement new features during this handoff.
- All project files were initially untracked/no HEAD. This changed with initial public commit; earlier review's no-commit finding is historical.
- `.gitignore` excludes full originals, matrices, reports, command logs and binary/native receipts. Cloud cannot recover those from clone. This handoff preserves findings/paths/results, not raw receipt contents.
- Public repository creation first used nanashili (active auth); user required Apollo Deploy, and repository was transferred. Use organization URL; old URL redirects but is not canonical.

## 10. Bugs / Known Issues

- **Latest volume lifecycle NEEDS VERIFICATION:** `capture` drops admission locks; `reopen` reacquires; `PinnedVolume.file` retains locks only while owners retain the descriptor. Trace descriptor lifetime into installed live VM and daemon restart. Prove no second RW session can attach while an old VM survives daemon death. Confirm actual jailer UID can open mounted backing file without unsafe mode/ownership changes. Check deterministic guest `/dev/vdc+` ordering vs Firecracker drive IDs, snapshot backing compatibility, mount partial failure/idempotency, duplicate catalog entries and nested/conflicting guest mount points. These are investigation tasks, not confirmed defects.
- **Latest diagnostics NEEDS VERIFICATION:** cap derives from active count × twice maximum configured memory/state size (potentially large); reservation is logical, not disk preallocation. Inspect startup scan behavior for partial jails, live sessions, foreign entries, symlink races, disk-full paths, migration/recovery on old sessions. Older VMs must cold-start to acquire new kernel file limits.
- **Cleanup ordering fixed in source:** two paths previously destroyed resources before detecting unexpected cgroup members. Focused fixtures passed; real kernel cgroup race/ownership testing remains.
- **Native proof missing:** current digest has no complete real Firecracker/jailer/OCI/PTY/files/snapshot/restart/upgrade/churn/performance/integration campaign. This cannot be fixed by unit tests alone.
- Docs may have stale remarks (e.g. systemd external networking rejection) after connected runtime changes; compare source before trusting any capability statement.
- Config sample intentionally invalid trusted hashes/paths. Native scripts historical assets absent after cleanup.

## 11. Failed or Rejected Approaches

- Never restore MicroSandbox, container/native host fallback, direct unjailed Firecracker, disabled seccomp, host networking fallback, unchecked artifacts/plain snapshots/required-sink discard.
- Never treat local macOS compile or fixtures as Linux runtime proof, or attribute old receipts to changed source.
- Do not auto-create/overmount private anchor during restart.
- Old v3 fixture rebuild discarded events/cursors; frozen historical schema and explicit preservation replaced it.
- First full suite failed on native tests missing env; explicit ignore/selected native run fixed harness, not a reason to fabricate native PASS.
- Historical native commands failed first on wrong Cargo path then missing Linux OpenOptions import; fixed and requalified narrowly.
- Volume agents spent too long designing without edits. One was interrupted/replaced. Avoid restarting endless design mapping; use source inspection, concrete small edits and focused checks.
- Volume tests initially used macOS symlinked `/var` tempfile path and SecureDir correctly rejected it; workspace tempdirs resolved fixture path.
- Concurrent edits briefly caused missing module/borrow/proof fields and incorrect SerialDevice limiter type. Later messages reported corrections; combined final verification still needed.

## 12. Tests and Verification

Historical local baseline before volume/diagnostics batch: `cargo test --locked --workspace --all-targets` exit 0, reported 190 passed with two native integration tests explicitly ignored. `cargo fmt --all -- --check`, locked all-target check and migration tests passed. These results do **not** apply to current digest.

Focused historical latest-batch results:

- `cargo test --lib session::cleanup::tests::`: 3 passed.
- `cargo test --lib session::reconcile_prelaunch::tests::`: 4 passed.
- `cargo test -p apollo-sandboxd --lib volume_catalog::tests -- --nocapture`: 4 passed.
- Diagnostics: three quota tests (atomic concurrent/max+one/idempotent Store) and startup stale/excess scanner, cleanup reservation-retain/release passed; final combined rerun unavailable.
- Independent old-digest reviewer ran prelaunch/migration/session process, failed-start replay, ancillary, OCI security, security contract, dependency/source limits successfully.

Historical narrow native final receipt: ignored local directory `qualification/private-anchor-recovery-final/20261004T081735Z`, source digest `a2651d337f40b7b123e0090755251be3c7e26192e553960a291680752fed3532`. Five invocations under `sudo -n ... /usr/bin/unshare --mount --propagation private`: three private-anchor tests, one ordinary asset recovery, six ignored recovery tests; all exit 0. No source changes during receipt commands. This is mount/recovery proof only, not full VM qualification.

Latest host cleanup receipt local `qualification/host-cleanup/20261004T081953Z`: exact fixture removal + audit exit 0; at 08:19:58Z all matching paths/processes/units/packages/sockets/cgroups empty, 7 mount namespaces scanned with 0 hits. Host state has not been rechecked for this handoff.

Current recommended commands (run after inspect, record current provenance):

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo test --locked --lib volume_catalog::tests
cargo test --locked --lib diagnostics_quota
cargo test --locked --lib startup_scan_accepts_reserved_files_and_rejects_stale_or_excess_files
cargo test --locked --lib session::cleanup::tests::
cargo test --locked --lib session::reconcile_prelaunch::tests::
cargo test --locked --test migration_contract
cargo test --locked --workspace --all-targets
python3 scripts/independence.py
python3 scripts/source_limits.py
python3 scripts/revision.py
```

Do not blindly run ignored native tests without secure assets/config and host authorization. No tests were run during handoff preparation, per scope; only source/Git inspection.

## 13. Performance Information

No defensible current-revision production measurements were recovered. Original targets: cached minimal create->GUEST_READY p95 <=1s; exec->child-running p95 <=100ms; idle daemon CPU near zero; no permanent daemon thread per sandbox; daemon memory proportional to active metadata, not VM memory; output pressure cannot cause unbounded RSS. Required reports originally separated daemon size/RSS/CPU/threads/FDs, VMM overhead/guest allocation/boot, and operation latency/throughput/recovery. Targets are requirements, not measured results. Do not publish standalone performance documents under the user's current repo policy.

## 14. Security Considerations

Use SO_PEERCRED before caller mutation authority; lease/generation/operation checks on mutations. PID numbers alone never authorize signaling/attachment: persisted start time/profile/jail/socket/cgroup/UID plus pidfds or equivalent strong identity. Orphans only cleaned with ownership proof. Guest telemetry advisory; host cgroups/KVM authoritative. Host inputs must be descriptor-pinned and verified; malicious layers/archives cannot escape extraction roots or create dangerous host nodes.

Secrets must not appear in Debug/logs/metrics/host durable state, snapshot metadata, or this handoff. Snapshot secret default rejects. Keys remain separate from manifests, strict filesystem permissions. API journals/events/output/transfers bounded. Treat guest-agent death as degraded/failure, never successful exec fiction.

Independent first report (local ignored `docs/review/INDEPENDENT_RED_TEAM_FINAL_CURRENT.md`) is bound to **old a2651d...**: release rejected, 0 Critical, 2 High, 2 unresolved mandatory Medium; 156 rows: 8 PASS, 4 FAIL, 104 PARTIAL, 39 UNPROVEN, 1 N/A. Findings:

1. RT-FINAL-001 HIGH: all additional volumes rejected (source remediation now present, unreviewed).
2. RT-FINAL-002 HIGH: full current-digest production qualification absent (still open).
3. RT-FINAL-003 MEDIUM: teardown before cgroup population check in normal/prelaunch cleanup (source remediation now present, unreviewed).
4. RT-FINAL-004 MEDIUM: no aggregate diagnostic storage/disk-full proof (source remediation now present, unreviewed).

No final RED_TEAM_RELEASE_APPROVED exists. User gate requires fresh independent skill-based subagent approval, 0 Critical/High/unresolved mandatory Medium, with every mandatory requirement proven. Do not suppress inconvenient findings or rubber-stamp implemented code.

## 15. Environment and Configuration

Local development was macOS arm64 (Apple M1 Pro), Rust/Cargo 1.93.1 in reviewer environment; workspace min 1.93. Native host historically Debian 13.7 x86_64, kernel `6.12.107+deb13-amd64`, Rust 1.96.0, hostname `vps-6b11ee2e`, SSH alias `tihan-apollo`. Host itself virtualized under KVM: original supported nested-KVM boundary and host-kernel compatibility still need assessment. SSH alias/keys not in repo; Cloud may lack connectivity. No credentials are included.

Cloud build: install Rust >=1.93, Cargo, Python3; registry/network access for locked dependencies. SQLite bundled. Linux native: root capabilities/jailer/KVM, cgroup v2/controllers, vsock, trusted runtime/kernel/initramfs/rootfs/catalogs/formatter, ext4/mount tools; systemd >=254 for candidate unit. Fuzz uses cargo-fuzz/nightly; optional cross-check scripts use Zig + musl targets.

Config `/etc/apollo-sandboxd/config.toml`; socket `/run/apollo-sandboxd/sandboxd.sock`; durable state/drive roots must be safe/private. Short `execution.operator_root=/run/asd`; host-boot provision `/run/asd/firecracker` distinct private mount root-owned 0700. Daemon verifies and never overmounts. `execution.cgroup_parent` points at delegated subtree. Root daemon currently required; `docs/SYSTEMD.md` documents exceptions, `KillMode=process` to retain VMs and no service cleanup killing them. Candidate unit not native-qualified.

Native harness variable names: `APOLLO_NATIVE_API_CONFIG`, `APOLLO_NATIVE_API_SOCKET`, `APOLLO_NATIVE_API_EVIDENCE`, `APOLLO_NATIVE_SOURCE_REVISION`, `APOLLO_NATIVE_BASE_DIGEST`, `APOLLO_NATIVE_RUNTIME_PROFILE`, `APOLLO_NATIVE_KERNEL_PROFILE`, `APOLLO_NATIVE_DAEMON_BIN`, `APOLLO_NATIVE_DAEMON_SHA256`, `APOLLO_NATIVE_SNAPSHOT_QUALIFY`; boot variables `APOLLO_NATIVE_CONFIG`, `APOLLO_NATIVE_OPERATOR_ROOT`, `APOLLO_NATIVE_STATE_DIR`, `APOLLO_NATIVE_CGROUP_PARENT`, `APOLLO_NATIVE_DRIVE_DIR`, `APOLLO_NATIVE_BASE_IMAGE`, `APOLLO_NATIVE_FORMATTER`, `APOLLO_NATIVE_FORMATTER_DIGEST`. Inspect tests for complete current set. Historical paths in scripts require reprovisioning and verification, not copying zero hashes.

No CI workflow directory was found. Do not assume GitHub has tested this commit.

## 16. Git / Working Tree State

At handoff preparation start:

- branch `main`, HEAD `b2af1ed` (initial commit, `Publish standalone Apollo Sandboxd under MIT`).
- remote origin `https://github.com/Apollo-Deploy/apollo-sandboxd.git`; local `main` tracks `origin/main` at same commit.
- no staged, unstaged, or visible untracked work; this handoff will be the only new file from this task.
- Published 296 files, including latest implementation batch. Earlier session had no HEAD/all untracked; those older statements are obsolete.
- Current executable-input digest `2beb86d9a2a9757d1e102b498e2cdcbf79aa3c068e8bde9652dc85571e2bd42f`, 288 inputs from `python3 scripts/revision.py`; scope includes source/protocols/guest/tests/scripts/packaging/Cargo/config/fuzz, excludes docs/evidence/build output.
- Ignored local material: `qualification/`, `docs/review/`, `docs/qualification/`, `docs/PRODUCTION_COMPLETION.md`, `docs/COMMANDS_RUN.md`, `docs/qualification-evidence.json`, fuzz corpus/artifacts/build data. Cloud clone does not contain it. Do not force-add it without user instruction.

This handoff will be committed/pushed as a separate documentation commit. Its own hash cannot be embedded accurately before commit; use `git log -1`. No new implementation is being committed by this handoff task. Preserve current working tree if it differs in Cloud.

## 17. Remaining Work

### P0 — Continue immediately

1. Read this file + applicable instructions, inspect Git/current source; run narrow volume/diagnostic/cleanup/migration tests then one full workspace suite. Fix actual failures, retain limits/ownership checks.
2. Review end-to-end volume descriptor/lock lifetime, jail UID access, restore pins, drive ordering/mount validation, restart exclusivity. Add regression attacks where evidence exposes a defect.
3. Review diagnostics reservations/schema migration/startup scan/cleanup release and actual disk-full handling. Confirm combined migration tests still preserve historical events/cursors.
4. Freeze a new executable digest and invoke mandatory independent Luna max implementation review with real source/tests/config and these requirements. Re-review after fixes.

### P1 — Required next

1. Establish authorized supported x86_64 KVM environment/access in Cloud; reprovision verified matching runtime/guest assets after cleanup. Do not claim old paths/assets still exist.
2. Native real jailer boot/API exec/PTY/raw FD sinks/files/OCI/persistence/checkpoint/encrypted snapshot/rebind/suspend/recovery on exact revision.
3. Crash injection for daemon/VMM/guest, wrong generations/operations, sink failure, corrupt/truncated state/snapshot, resource saturation/foreign cleanup.
4. Runtime A/B coexistence, daemon rolling upgrade/protocol/state compatibility; host reboot only with explicit dedicated-host authorization.
5. Independent review approval gate after exact-revision proof; no false completion claims.

### P2 — Important later (still mandatory for original production completion)

1. >20,000 lifecycle churn/leak checks and concurrent workloads/file/image/snapshot quotas.
2. Full parser fuzz/property coverage, measured original latency/resource targets.
3. Reference/Docker-capable guest qualification and clean standalone host proof.
4. External netd network mapping and logd raw-byte FD integration without crate coupling.
5. Qualify systemd installation, supply-chain provenance/SBOM, safe GC, all required capabilities against source and runtime.
6. aarch64 only when user restores scope/provides host; not a prerequisite to current x86_64 iteration.

### P3 — Optional / future

Contributor documentation/CI improvements consistent with current public repo policy. Do not recast mandatory missing capabilities as future versions. Permanent non-goals remain outside product.

## 18. Recommended Next Task

**Verify and repair the published additional-volume and diagnostics batch before new features.** At the cloned HEAD, inspect `src/volume_catalog.rs`, `src/state/session.rs`, `src/api/runtime_authority.rs`, `runtime_boot.rs`, `runtime_recover.rs`, `runtime_service.rs`, `src/session/assets.rs`, `asset_setup.rs`, `configure.rs`, `boot.rs`, `cleanup.rs`, `reconcile_prelaunch.rs`, `diagnostics.rs`, `src/state/diagnostics_quota.rs`, `schema.rs`, `guest-agent/src/volumes.rs`, and guest protocol messages/callers. Follow all resource lifetimes and error paths. Run commands in section 12. Establish the exact current test outcome, independently attack RW locking across surviving VMs/restart and diagnostics recovery/cleanup, then fix only demonstrated defects. Once stable, request/use the mandated independent implementation review skill subagent (Luna max) against the frozen digest. If Cloud lacks KVM/SSH/skill access, clearly separate local source/test work from blocked native proof and continue unaffected work.

## 19. Suggested Cloud Bootstrap Prompt

> Continue Apollo Sandboxd development from this repository. Read CODEX_HANDOFF.md completely, then all applicable AGENTS.md instructions. Inspect actual source, Git status/diff/log and configuration rather than blindly trusting the handoff. Preserve standalone Firecracker+jailer/vsock architecture, fail-closed trust boundaries, generic network/FD integrations, bounded resources, durable intent/idempotency/generation semantics, MIT license and Apollo-Deploy ownership. Keep performance/verdict/review/qualification documents out of the public repository per user policy. Do not reimplement completed work or repeat rejected approaches without new evidence. Active qualification scope is x86_64 only; no Astra agents, use GPT-6 Luna max sparingly. Begin with section 18: verify/fix the published volume, diagnostic-quota, cleanup and migration batch with narrow tests and then one full suite. Invoke the mandatory independent Red Team Implementation skill subagent before any production-complete claim, fix and re-review blocking findings. Native host tihan-apollo was cleaned of Apollo/Docker assets; verify access/environment and reprovision trusted artifacts before native tests. Do not reboot without explicit authorization. Report exact current-revision proof and unresolved gaps honestly. Do not assume ignored local reports/receipts exist in Cloud.
