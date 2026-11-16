# Filesystem research: virtual config delivery, durable workspaces, and Landlock alternatives

Research date: 2026-11-16 UTC. This is a comparative research report. It is not
an RFC, an approved design, or an implementation plan, and nothing here was
built, run, or benchmarked. The only measurements cited as ours are the ones
already recorded in [RESULTS-PR3832.md](RESULTS-PR3832.md) and
[PERFORMANCE-IDEAS.md](PERFORMANCE-IDEAS.md).

Follow-up: the [compatible implementation and results](RESULTS-COMPATIBLE.md)
cover revision caching and simpler classification with seccomp and Landlock
retained. The research findings and proposals below describe the earlier
baseline.

## Executive conclusion

1. **The file-open cost is the seccomp notification round trip, not Landlock.**
   Our harness attributes about 14 µs of a 17 µs intercepted open to the
   notification itself and 0.15 µs to a Landlock domain
   ([PERFORMANCE-IDEAS.md](PERFORMANCE-IDEAS.md)). Substituting another
   authorization mechanism for Landlock while every open still notifies does
   not remove that overhead, so it cannot recover the regression measured in
   [RESULTS-PR3832.md](RESULTS-PR3832.md). A redesign that also removes the
   global open notification could; the gain would come from removing the
   notification, not from removing Landlock. Replacing Landlock stays a
   candidate goal for other reasons; no performance evidence here supports it
   by itself.
2. **No bookmarked project removes that cost inside our current constraints.**
   Where the durable-workspace products reviewed offer a mounted interface for
   arbitrary Linux binaries, that interface is FUSE: verified for AgentFS,
   LayerFS, drive9/Daytona, and Archil; an author claim for Tensorlake. This
   says nothing about their SDK and API paths or about every possible backend:
   Tines uses a custom gVisor gofer, and Tensorlake claims a block device. A
   FUSE mount needs `/dev/fuse` and an authorized mount step. None of these
   products is an access-control mechanism, and none replaces Landlock.
3. **The closest architectural peer keeps Landlock.** Sandlock uses the same
   Landlock + seccomp-notify combination we do, and its documentation states
   that path-based control belongs in Landlock because a notification
   supervisor cannot safely judge pathnames.
4. **One suggested optimization is blocked by the kernel as worded.** Linux
   refuses a second `SECCOMP_FILTER_FLAG_NEW_LISTENER` filter on a task that
   already has one (`EBUSY`), so "separate file and network listeners" cannot be
   two stacked listeners on the workload. The goal behind it (apply the
   synchronous-wakeup hint to file opens without hurting network tails) needs a
   different shape; see experiment 1.
5. **Two directions make ordinary opens cheap again: reduce the round trip, or
   remove it from ordinary opens.** Reducing it is measured: 16.3 → 4.1 µs
   single-threaded with the wakeup hint, with multi-thread regressions.
   Removing it means the filter stops notifying on `open` and another
   kernel-mediated layer delivers the virtual files. One runtime-private FUSE
   mount is one candidate; a gVisor Sentry-internal file and a guest-kernel
   VFS are others. Each is a deployment change, and none uses a per-config-file
   infrastructure mount, which the user excludes. This direction counts only
   if a kernel VFS hook satisfies the user's kernel-hook requirement. If that
   requirement means seccomp user notification on every open, the cost stays
   and only the first direction applies. The report does not resolve which
   reading is intended.
6. **Recommended order**: (a) a faster seccomp + memfd path with Landlock
   retained; (b) a feasibility spike for one runtime-private synthetic mount,
   if a kernel VFS hook is acceptable;
   (c) treat durable workspaces as a separate, optional backend plugin; (d)
   gVisor and VM-internal designs only as explicitly scoped redesigns.

## Method and evidence labels

Each bookmarked post was fetched through X's public syndication endpoint on
2026-11-16. That endpoint returns only the first ~280 characters of long posts
and no media, so most posts are **partially accessible**. I then located the
authors' repositories and documentation and read those directly.

| Label | Meaning |
|---|---|
| **Verified** | Read in a primary source on 2026-11-16 (official docs, the author's repository at the commit given, kernel docs or source). Vendor documentation verifies what the vendor states, not that the behavior holds. |
| **Author claim** | Stated in the author's post or self-published benchmark; not independently checked. |
| **Bookmark-only** | Appears only in the attachment's summary. The attachment says its summaries were not freshly verified, and the text was not in the accessible part of the post. |
| **Inference** | My reasoning from verified facts. Needs an experiment before anyone relies on it. |
| **Unknown** | Not documented in what I read. |

## What our own measurements establish

- PR #3832 made every `open`, `openat`, and `openat2` notify, because classic
  seccomp BPF cannot read a path string. Open/read/close went from 100.5 ms to
  838.4 ms per 50,000 iterations (8.34×); reads on an existing descriptor
  changed 1.3% ([RESULTS-PR3832.md](RESULTS-PR3832.md)).
- Harness p50: native 1.0 µs, notify-only 14.9 µs, full handler 17.0 µs; a
  Landlock domain adds 0.15 µs to a native open
  ([PERFORMANCE-IDEAS.md](PERFORMANCE-IDEAS.md)).
- The synchronous-wakeup hint and extra receivers on the shared listener were
  both measured and both rejected for multi-thread or network regressions.
- The provider-open handler builds a new sealed memfd for every provider open
  (`sealed_memfd` in `crates/openshell-sandbox/src/provider_files.rs`), then
  reopens it through `/proc/self/fd` to get a read-only description. Caching
  the sealed object per revision would speed provider opens only. It does
  nothing for the ordinary opens that dominate the regression.
- The working tree contains an uncommitted volume-backed native provider
  store. The user has since rejected that architecture. It is left untouched
  and is not a recommended direction in this report.

A point that shapes everything below: today the notification is a
**virtualization hook**, and Landlock is the **authorization**. When the broker
continues an ordinary open, the kernel re-reads the path and Landlock judges
it. A workload that swaps the pointer after the broker's prefix check gains
nothing, because no real file exists at the provider path. That safety
argument depends on a kernel-side path authority existing.

## Three separate responsibilities

| Responsibility | What it must do | What does not satisfy it |
|---|---|---|
| Config virtualization | Show supervisor-held file content at fixed paths to any Linux binary, atomically updatable, through a kernel hook | SDK or tool-shaped file APIs; per-file infrastructure volume mounts (excluded by the user) |
| Durable workspace storage | Keep a writable tree beyond the sandbox's life; snapshot, fork, share | A sandbox boundary; Landlock |
| Filesystem access control | Decide per path what the workload may read, write, execute, even against a hostile same-UID process; protect runtime keys inside the sandbox | A durable storage product; FUSE alone; a container or VM boundary without a per-path policy inside it |

## Decision matrix

"Config", "Workspace", and "Landlock role" say whether the approach can serve
each responsibility. "Evidence" separates measurement from speculation.

| Approach | Config | Workspace | Landlock role | Kernel hook; arbitrary binaries | Per-file infra volumes | New deployment requirement | Overhead evidence | Effort; open limits |
|---|---|---|---|---|---|---|---|---|
| Current: notify every open + memfd, Landlock | Yes | No | Kept | seccomp notify; yes | None | None | **Measured**: +14–15 µs per open | Baseline |
| Faster notify (one listener, wakeup hint scoped by dispatch design; memfd cache; minimal handler) | Yes | No | Kept | Same | None | Kernel with `SECCOMP_IOCTL_NOTIF_SET_FLAGS`, runtime-probed | **Measured** 4.1 µs p50 single thread with hint; **measured** multi-thread tail regressions. New dispatch shape: speculation | Small to medium; may not fix tails |
| Runtime-private FUSE mount served by the supervisor | Yes, if a VFS hook meets the kernel-hook requirement | No | Kept (mount before Landlock) | VFS → FUSE; yes | None; one synthetic mount | `/dev/fuse` access and an authorized mount step: the driver, a delegated helper, or a user + mount namespace at bootstrap. The serving daemon needs no added capability once it holds the descriptor (**inference**) | **None of ours.** Ordinary opens return to native by construction; provider-open cost unmeasured | Medium to large per driver; mount authorization unresolved |
| Runtime-populated tmpfs | Yes | No | Kept and relied on to separate same-UID writer from reader | VFS; yes | None; one mount | Mount by driver or namespace | Native tmpfs speed is expected; unmeasured here | Same same-UID separation problem as the rejected store, without the volume |
| AgentFS | No (not its purpose) | Yes, single SQLite file | No | FUSE; yes | n/a | `/dev/fuse`, user namespaces for `agentfs run` | Unmeasured by us | Beta; lock and SQLite-on-AgentFS semantics unknown |
| LayerFS | No | Yes, branches and commits on one host | No | FUSE; yes, minus FIFOs, sockets, devices, set-id | n/a | Docker, `/dev/fuse`; one Linux kernel and a local ext4, xfs, or btrfs store | **Author claim**, single-sample | SQLite WAL with `synchronous=OFF`; no crash durability claimed; not a cross-host shared disk |
| Tensorlake file systems | No | Yes, shared timeline | No | Mount; mechanism per author is FUSE | n/a | Hosted service; FUSE-capable sandbox | **Author claim** only | Same-path writes silently last-writer-wins |
| TiDB Cloud Filesystem / drive9 | No | Yes | No | FUSE | n/a | Hosted service or drive9 server; FUSE | None | Public preview; writes need an explicit drain |
| Archil | No | Yes | No | FUSE | n/a | `/dev/fuse`, root, `CAP_SYS_ADMIN` | **Vendor-published**, not checked | Locks are per client; no `renameat2` flags |
| Sandlock design | Its `/proc` virtualization is the same pattern as ours | COW staging only | Kept; it is built on Landlock | seccomp notify; yes | None | Linux 6.12+ | **Author claim**: Redis at 97% of bare metal; no open microbenchmark | A peer to learn from, not a replacement |
| gVisor (runsc) with a custom gofer or synthetic file | Yes, inside the Sentry | Yes (Tines does this) | Replaced by the Sentry VFS and gofer | Sentry intercepts all syscalls; most binaries | None | runsc runtime on every node; custom runsc build | **Verified vendor**: Directfs made `stat` over 2× faster than gofer RPC; nothing against native | Redesign. Current broker cannot run nested: no `NEW_LISTENER` |
| VM boundary (virtiofs or block) | Via guest-internal mechanism | Yes | Not by itself; per-path policy still needed in the guest | Guest kernel VFS; yes | Depends on design | KVM or equivalent; host daemon for virtiofs | None of ours | VM driver only; no `/dev/kvm` on the benchmark host |
| Host LSM (AppArmor, SELinux, BPF LSM) | No | No | Candidate replacement, as host policy; no evidence it is faster or safer here | LSM hooks; yes | None | Privileged host agent and per-sandbox policy loading | None | Large; policy loading sits outside a capability-free sandbox |
| Mount-namespace view (bubblewrap style) | Could host the synthetic mount | No | Candidate for an explicitly bounded policy: absent paths plus read-only and `noexec` trees, with UID or process separation, descriptor sanitization, and seccomp. Not a drop-in for the current same-UID layout | VFS; yes | None | Privileged or delegated bootstrap, or unprivileged user namespaces | None | Redesign with changed policy semantics; user namespaces are restricted on the benchmark host |

## How each reviewed system actually handles files

### AgentFS (Turso)

Source: [tursodatabase/agentfs](https://github.com/tursodatabase/agentfs) at
`0a014ebd` (commit dated 2026-06-03; latest release v0.6.4, 2026-03-25).

- **Verified.** The README marks it beta. Storage is one SQLite file with an
  inode design: `fs_inode`, `fs_dentry`, and `fs_data` holding fixed 4,096-byte
  chunks keyed by inode and chunk index
  ([SPEC.md](https://github.com/tursodatabase/agentfs/blob/main/SPEC.md)).
  An overlay mode records deletions in `fs_whiteout` over a read-only base.
- **Verified.** Linux binaries reach it through FUSE; macOS uses NFS.
  `agentfs run` uses "FUSE + overlay filesystem with user namespaces" on Linux,
  with an experimental ptrace mode
  ([MANUAL.md](https://github.com/tursodatabase/agentfs/blob/main/MANUAL.md)).
- **Verified.** The FUSE layer gives the kernel entries that never expire
  (`TTL = Duration::MAX`) and invalidates them explicitly after mutations. It
  enables writeback caching, parallel directory operations, async reads, and
  zero-message `opendir`
  ([cli/src/fuse.rs](https://github.com/tursodatabase/agentfs/blob/main/cli/src/fuse.rs)).
  This is the caching pattern a config filesystem would want.
- **Verified.** Snapshot is a file copy of the database; cloud sync targets a
  Turso database and cannot be combined with local encryption.
- **Unknown.** `fcntl`/`flock` behavior (I found no lock handlers in
  `fuse.rs`), shared-`mmap` behavior under writeback caching, crash consistency
  of in-flight writes, and whether a SQLite database in WAL mode stored
  *inside* an AgentFS mount is safe. Two mounts of one database file are not
  documented as a supported multi-writer mode.
- **Bookmark post** ([@glcst, 2026-01-12](https://x.com/glcst/status/2010780029345534310)):
  first 279 characters accessible and consistent with the spec.

### Sandlock (Multikernel)

Source: [multikernel/sandlock](https://github.com/multikernel/sandlock) at
`ca0c9f1b` (2026-11-16; release v0.9.1, 2026-11-04).

- **Verified.** It confines with Landlock (filesystem, network, IPC),
  seccomp-bpf, and seccomp user notification: "No root, no cgroups, no
  containers." It needs Linux 6.12+
  ([README](https://github.com/multikernel/sandlock/blob/main/README.md)).
- **Verified.** COW is syscall interception, not a mount: the supervisor
  handles `openat`, `unlinkat`, `mkdirat`, `renameat2`, and `getdents64`,
  staging writes in an upper directory and resolving reads upper-then-lower.
  Only regular files, directories, and symlinks are staged
  ([docs/architecture.md](https://github.com/multikernel/sandlock/blob/main/docs/architecture.md)).
- **Verified.** Its policy-callback documentation refuses to expose path
  strings, "because seccomp user notification re-reads user-memory pointers
  after `Continue`", and says path-based control belongs in static Landlock
  rules. For `execve` it freezes all peer tasks, re-reads `argv`, and denies on
  mismatch
  ([docs/policy-fn.md](https://github.com/multikernel/sandlock/blob/main/docs/policy-fn.md)).
- **Verified.** Nested Sandlock must run without a supervisor because the
  kernel allows one listener per task
  ([docs/sandbox-reference.md](https://github.com/multikernel/sandlock/blob/main/docs/sandbox-reference.md)).
- **Author claim.** README performance table (Redis at 97.1% of bare metal,
  ~5 ms startup overhead). It has no file-open microbenchmark, so it tells us
  nothing about our 15 µs.
- **Bookmark posts**: releases 0.8.8 (2026-09-16) and 0.8.9 (2026-09-27) exist
  with matching dates. The deferred-commit feature matches the documented COW
  commit/abort model. The symlink-anchoring detail is **bookmark-only**; I did
  not find it in the release text I read.

### gVisor, and Tines 3B

Sources: [google/gvisor](https://github.com/google/gvisor) at `89cacada`
(2026-11-16);
[A versioned filesystem for disposable sandboxes](https://www.shayon.dev/post/2026/283/versioned-filesystem-for-disposable-sandboxes/)
(Shayon Mukherjee, 2026-10-10); [gvisor.dev/users](https://gvisor.dev/users/).

- **Verified, current source.**
  [`sys_seccomp.go`](https://github.com/google/gvisor/blob/master/pkg/sentry/syscalls/linux/sys_seccomp.go)
  accepts only `SECCOMP_SET_MODE_FILTER` and only the `TSYNC` flag; anything
  else returns `EINVAL`. `SECCOMP_FILTER_FLAG_NEW_LISTENER` is therefore
  rejected. The OpenShell broker cannot run as a nested gVisor workload.
- **Verified.** File access goes through a separate gofer process over LISAFS.
  Directfs (default) donates mount-point descriptors to the Sentry, which then
  uses descriptor-relative syscalls with `O_NOFOLLOW` enforced by seccomp. The
  sandbox mount namespace is always empty
  ([filesystem.md](https://github.com/google/gvisor/blob/master/g3doc/user_guide/filesystem.md)).
- **Verified.** "Custom Gofer Extensions": a custom runsc build registers an
  extension under `runsc/gofer/fs/extension` that claims mounts by path and
  supplies its own `lisafs.ConnectionImpl`. This is a build-time integration,
  not a runtime flag.
- **Verified.**
  [`kernfs.DynamicBytesFile`](https://github.com/google/gvisor/blob/master/pkg/sentry/fsimpl/kernfs/dynamic_bytes_file.go)
  is a read-only Sentry-internal file backed by a dynamic byte source. It is the
  natural machinery for a synthetic config file that needs no host mount.
- **Verified vendor benchmark.** Directfs made a `stat` microbenchmark more
  than 2× faster than gofer RPC and cut real workload time 12%
  ([Directfs blog, 2023-06-27](https://gvisor.dev/blog/2023/06/27/directfs/)).
  That compares gVisor to gVisor, not to a native container.
- **Verified (Tines article).** A custom gofer, Nest, serves the workspace. At
  open it gives the sandbox a real descriptor to a host tmpfs copy, so file
  I/O stays local. Snapshots are per step: `fsync` flushes the local copy and
  is not a commit. A successful step commits by compare-and-swap on the
  snapshot pointer, and concurrent changes to the same file conflict.
- **Inference.** The design avoids the shared-SQLite question instead of
  solving it: steps work on private copies of one snapshot, so no two steps
  share a live WAL, and a database changed by two steps conflicts as a whole
  file.
- **Inference (design caution).** A real descriptor is a fast path for
  workload-controlled data only. It is not a pattern for bytes the trusted
  side later reads as policy or credentials.
- **Bookmark-only.** That gVisor is joining the CNCF.

### Box (identity resolved with medium confidence)

- **Identity.** The post is by @AniC_dev about "box", "a forkable full-VM AI
  sandbox". `https://box.ascii.dev/` now redirects to
  [boat.dev](https://boat.dev/) (**verified** redirect), published by ASCII.
  The link from @AniC_dev to that product rests on third-party listing snippets
  I could not open directly, hence medium confidence. It is **not** Box.com
  (which appears in Daytona's mount docs as a storage provider) and **not**
  Upstash Box.
- **Verified** ([docs.boat.dev/snapshots](https://docs.boat.dev/snapshots)).
  The disk is saved every minute and at stop. Memory, running programs, open
  connections, `/tmp`, and `~/.cache` are not saved; a resume after ten minutes
  "is like a reboot"; a machine failure loses writes since the last snapshot.
  After resume, container images "load in the background".
- **Bookmark-only.** Metadata-first restore through FUSE, background content
  download, and learned access order. The public docs I read do not describe
  the mechanism. The accessible post text says only "diff-based filesystem
  snapshot system", "not CoW disks", "not hypervisor magic".

### LayerFS (identity resolved)

Source: [Ephemeral-AI-Lab/layerfs](https://github.com/Ephemeral-AI-Lab/layerfs)
at `7d42d0b5` (2026-11-16; v1.1.0, MIT), and its current docs:
[Help](https://layerfs.ai/docs/help/) and
[Platform and limits](https://layerfs.ai/docs/platform/). The @rustaceans_rs wording matches
this repository's description, and its top contributor handle resembles the
second poster's. A different Rust project, `sammwyy/layerfs`, shares the name and
is not the bookmarked one.

- **Verified.** One SQLite file holds every branch, commit, and content
  object; content is chunked and stored once. A workspace is a FUSE view
  (committed root plus a private overlay) served by a daemon inside a sandbox.
  File tools can bypass the mount and talk to the store in process.
- **Verified limits, from its README.** "no crash or power-loss durability";
  the FUSE view omits FIFOs, sockets, device nodes, set-id bits, and separate
  atime/ctime; two commits changing one file are refused unless a
  last-writer-wins rule names it.
- **Verified (current docs).** The sole Store profile uses SQLite WAL with
  `synchronous=OFF` and offers no crash-durability guarantee. The docs
  distinguish an application crash, which preserves acknowledged commits,
  from an operating-system crash or power loss, which can lose recent
  history or corrupt the Store.
- **Verified (current docs).** All processes opening a project's Store must
  run under one Linux kernel, and the Store must sit on a local ext4, xfs, or
  btrfs filesystem. NFS, virtiofs, and a second machine are refused as
  `Unsupported` before any write, because SQLite's locks and LayerFS's writer
  coordination only work within one kernel.
- **Inference.** LayerFS branching is single-host version control for
  sandboxes that share a kernel. It makes no claim to be a durable disk shared
  across hosts or clouds, and should not be compared with Archil, Tensorlake,
  or TiDB Cloud Filesystem on that axis.
- **Author claim.** Benchmarks are single-sample on an arm64 Mac under Docker
  Desktop, against libfuse passthrough rather than a native filesystem. The
  README reports sequential write at 0.31× of passthrough. It reports 19.9×
  smaller than Btrfs + zstd on one history; the bookmark summary says "roughly
  10×", which I could not reconcile because the post text is truncated.

### Tensorlake

Sources: [Architecture](https://docs.tensorlake.ai/filesystems/architecture.md),
[Concurrent Writes](https://docs.tensorlake.ai/filesystems/concurrent-writes.md),
[Core Concepts](https://docs.tensorlake.ai/filesystems/core-concepts.md),
[Snapshot and Clone](https://docs.tensorlake.ai/sandboxes/snapshots.md).

- **Verified (vendor docs).** Metadata in a control plane, content-addressed
  blobs in a data plane, lazy fetch on read. Writes go to a crash-safe local
  journal, then to a per-session server WAL as autosave checkpoints, about a
  second after writes settle and at least every five seconds under continuous
  writing. Other mounts do not see bytes still in a local batch.
- **Verified.** Concurrent writers to different paths merge; the same path is
  silently last-writer-wins. That is unsafe for a shared SQLite file, and the
  docs recommend partitioning writers by directory.
- **Verified.** Sandbox checkpoints come in two kinds: `filesystem` (cold boot)
  and `memory` (processes preserved).
- **Author claim.** FUSE on Linux and FSKit on macOS; a block filesystem behind
  virtio-blk that is "~2–4× faster" than three competitors on SQLite. The docs
  I read call the mount "a normal POSIX compliant directory" and do not name
  the mechanism.

### TiDB Cloud Filesystem, drive9, and Daytona

Sources: [Daytona: Mount External Storage](https://www.daytona.io/docs/en/mount-external-storage/),
[PingCAP product page](https://www.pingcap.com/tidb/tidb-cloud-filesystem/),
[mem9-ai/drive9](https://github.com/mem9-ai/drive9) at `ce1cca42`.

- **Verified.** Daytona documents the mount; the product is in public preview.
  Daytona states that all its external mounts and its own volumes are
  FUSE-based. "The mount caches writes locally and uploads them in the
  background"; a drain command must run before another sandbox reads or the
  sandbox is deleted.
- **Verified (drive9).** FUSE mount with selectable durability profiles. The
  default buffers writes locally, and `fsync` may be satisfied by a local
  journal on high-latency links
  ([fuse-durability-policy.md](https://github.com/mem9-ai/drive9/blob/main/docs/design/fuse-durability-policy.md)).
  Its README shows a TiDB/MySQL-compatible metadata store.
- **Uncertain match.** That drive9 is the implementation of TiDB Cloud
  Filesystem rests on @siddontang's post linking
  [drive9 PR #1022](https://github.com/mem9-ai/drive9/pull/1022) (merged
  2026-10-19). I did not find PingCAP documentation stating it.
- **Unknown.** Cross-mount lock semantics and SQLite WAL safety.

### Archil

Sources: [Consistency](https://docs.archil.com/details/consistency.md),
[Application Compatibility](https://docs.archil.com/details/support.md),
[Architecture](https://docs.archil.com/details/architecture.md),
[Mount in a container](https://docs.archil.com/mounting/containers.md).

- **Verified.** A FUSE client speaking a custom protocol to a hosted cache in
  front of object storage. A container that mounts it "needs `/dev/fuse`, root,
  and the `CAP_SYS_ADMIN` capability"; local Docker needs `--privileged`.
- **Verified.** Writes are buffered and sent about once a second; `fsync`
  waits for durability; `close` does not wait on exclusive or shared mounts.
  Attributes are cached up to 30 seconds and listings up to five minutes.
  Unsent writes are lost if the client dies, and a crashed client's write
  delegations stay in place until revoked.
- **Verified.** `flock` and `fcntl` locks work "for every process on a
  client". Across clients, coordination is by checkout delegations, or not at
  all in conditional mode. `renameat2` flags, including `RENAME_EXCHANGE`,
  fail with `EINVAL`.
- **Inference.** A SQLite file opened by two clients on a conditional mount
  has no cross-client locking, so it is unsafe. Archil offers a separate
  [SQLite API](https://docs.archil.com/compute/sqlite.md) for multi-client use,
  which is an SDK and not a file interface.

### pi-durable-disk and pi-transport (AgentRun, on Archil)

Sources: [AgentRun extensions page](https://agentrun.ai/extensions/runs-anywhere)
and the repository it links,
[Parcha-ai/agentrun](https://github.com/Parcha-ai/agentrun). I read the page;
the package READMEs were not read in this pass.

- **Verified (vendor page).** A run is one directory on an Archil disk holding
  the agent's SQLite store, its workspace, and a `run.json` with status,
  generation, and holder. Opening a run mounts it and takes an exclusive
  claim. Competing holders are rejected, and losing ownership fences out
  further writes. `release()` seals the run, gives up
  the claim, and unmounts; a move to another host happens at a step boundary
  after release, and the next opener is the next generation.
- **Verified (vendor page).** This release supports Archil as its disk backend
  because it supplies the exclusive ownership and fencing the package needs.
  The package supplies no sandbox; commands execute as the run user. The
  packages are beta (`0.1.0-beta.33`), and pi-transport is marked
  experimental.
- **Inference.** This is an application-level run lock with fencing: one
  writer per run, handed over explicitly. It is not cross-client POSIX
  locking. Archil documents `flock` and `fcntl` as per client, and this
  package avoids needing more by never having two live holders. It is not
  evidence that a SQLite file shared by concurrent mounts is safe.
- **Inference.** The useful part for a workspace contract is the handoff
  model: single holder, generation counter, release before migration. It adds
  no isolation and inherits Archil's mount requirements.

### virtiofs

Sources: [kernel virtiofs documentation](https://docs.kernel.org/filesystems/virtiofs.html)
(7.4.0-rc3 docs), [virtio-fs.gitlab.io](https://virtio-fs.gitlab.io/).

- **Verified.** The guest kernel is a FUSE client; requests travel over
  virtqueues to a host daemon instead of `/dev/fuse`. DAX, which maps the host
  page cache into the guest, is described as experimental.
- **Verified locally.** Our VM driver already uses libkrun virtiofs for
  optional host directory shares (`crates/openshell-driver-vm/README.md`).
- **Inference.** virtiofs moves bytes across a VM boundary. It is a transport
  for a workspace or a synthetic share, not a per-path policy.

## Can something replace Landlock's filesystem role?

Kernel facts first. Landlock cannot yet restrict `chdir`, `stat`, `flock`,
`chmod`, `chown`, `setxattr`, `utime`, `fcntl`, or `access`; a
Landlock-restricted thread cannot `mount` or `pivot_root`; and the current
documentation describes capability and namespace rules from ABI v12
([Landlock docs](https://docs.kernel.org/userspace-api/landlock.html)).
`seccomp_unotify(2)` says the mechanism "must not be used to make security
policy decisions" because of the argument-rewrite race
([man page](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)).

| Candidate | Assessment |
|---|---|
| **seccomp-only path policy** | Not viable as a `CONTINUE`-based design: the kernel re-reads the path after the supervisor decides. A sound version must *emulate* every path syscall (open in the supervisor with `openat2` `RESOLVE_*` constraints, inject the descriptor), and also cover `execve`, `mmap` of injected files, inherited and passed descriptors, `/proc/*/fd` re-opens, hard links, renames, bind aliases, `io_uring`, and live policy updates, from a supervisor the workload cannot signal or ptrace. Sandlock, which does emulate for COW, still leaves authorization to Landlock. Every open would pay the notification cost permanently. Not recommended. |
| **Mount-namespace view (bubblewrap, Flatpak style)** | Hides what is not mounted, so "deny" becomes "absent", and it does enforce some operation distinctions: a read-only mount refuses writes and a `noexec` mount refuses execution, per mount rather than per path. A properly isolated private view with separate read-only and read-write trees, descriptor sanitization, UID or process separation between runtime and workload, and seccomp is a candidate replacement for an explicitly bounded filesystem policy. The semantics change: granularity is the mount, narrowing a live policy means remounting, and bootstrap needs privilege or delegation. It is not a drop-in replacement in the current layout, where runtime files sit in the same view under the workload's UID. bubblewrap's README says it "is not a complete, ready-made sandbox with a specific security policy" and relies on user namespaces ([README](https://github.com/containers/bubblewrap/blob/main/README.md)). Docker's default seccomp profile denies `mount` without `CAP_SYS_ADMIN` and allows only user-namespace `unshare` ([Docker docs](https://docs.docker.com/engine/security/seccomp/)); the benchmark host also has `apparmor_restrict_unprivileged_userns=1`. Flatpak's own documentation was not reviewed. Today it is a complement that could host a synthetic mount; as a replacement it is a redesign candidate, unevaluated. |
| **Host LSMs** | AppArmor and SELinux can express per-path or label policy with no per-open user-space round trip. BPF LSM is documented for "privileged users to implement system-wide MAC" ([kernel docs](https://docs.kernel.org/bpf/prog_lsm.html)). All three need a privileged host agent to load per-sandbox policy, so they are a deployment change outside the sandbox's control, and their availability varies by distribution and managed Kubernetes offering. They are candidates for operator-managed hosts. Nothing reviewed shows they would be faster or safer than Landlock for this policy; that would need its own measurement and threat analysis. |
| **gVisor Sentry VFS** | Does replace host-kernel path mediation: the Sentry resolves paths, and the gofer or Directfs constrains what the Sentry can reach. Config files could be Sentry-internal synthetic files. Costs: a custom runsc build on every node, a rewritten broker (no `NEW_LISTENER`), gVisor's own syscall overhead, and a different compatibility surface. A redesign, evaluated on its own merits. |
| **VM-backed isolation** | A stronger outer boundary. Inside the guest, the trusted runtime and the workload still share a kernel, so per-path policy and runtime-key protection still need Landlock, or a guest-internal equivalent. It does not remove the need; it relocates it. |
| **FUSE** | Not confinement. It decides what one mount shows, not what the process may reach elsewhere. |
| **WASI, just-bash, tool-shaped file APIs** | Not transparent to native Python, Node, or Claude Code binaries. Out of scope for enforcement. |

Conclusion: Landlock is not the only kernel authority over paths. Ordinary
ownership and mode checks, mount flags, and host LSMs all decide access too,
and a redesigned isolation layout (separate UIDs, a private mount view, a
Sentry, or a guest) could move the policy onto them. Within the current
supported bootstrap, which is capability-free, has no host agent, and runs
runtime and workload under one UID, Landlock is the mechanism that expresses
the per-path policy without new privilege. Inside that design the practical
question is what to pair it with. Replacing it is a redesign question, with
changed semantics to state explicitly and no performance case by itself.

## Config delivery: which mounts are and are not excluded

| Case | Description | Status |
|---|---|---|
| A | One infrastructure volume or bind mount per config file | Excluded by the user |
| B | Volume-backed store mounted twice, published by directory exchange (the uncommitted experiment) | Rejected by the user; preserved, not recommended |
| C1 | One runtime-private **FUSE** filesystem at the provider root, served from supervisor memory | Not excluded as a mount. Needs `/dev/fuse` and an authorized mount step: a deployment change. Qualifies only if a kernel VFS hook meets the kernel-hook requirement |
| C2 | One runtime-populated **tmpfs** at the provider root | Not excluded, but the runtime and workload share a UID, so it needs the same Landlock-based writer/reader separation that made B awkward |
| D | Sentry-internal synthetic files under gVisor | No host mount at all; redesign |
| E | Guest-internal synthetic filesystem in a VM | VM driver only |

The condition on C1, D, and E: they remove ordinary-open notifications only if
a kernel VFS or FUSE hook satisfies the user's kernel-hook requirement. If the
requirement is seccomp user notification on every open, the notification cost
remains under any of them, and experiment 1 is the only route. The user's
wording allows either reading; this report carries both and does not choose.

Why C1 is the interesting one under the VFS reading (**inference**, to be
tested):

- The kernel VFS becomes the hook. The seccomp filter no longer needs to
  notify on `open`, so ordinary opens return to native cost by construction.
- There is no pointer race: the kernel resolves the path and asks the daemon
  about inodes.
- The FUSE protocol has zero-message opens (`FUSE_NO_OPEN_SUPPORT`),
  keep-cache opens, and explicit entry and inode invalidation
  ([`fuse.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/fuse.h)),
  and AgentFS shows the never-expire-plus-invalidate pattern in shipping
  code. A warm provider open might need no daemon round trip. Unmeasured.
- Update semantics can match today's: publish each revision as a new inode and
  switch the directory entry, so a descriptor opened earlier keeps its
  revision.
- Unresolved: who mounts. Two things are separate here. Serving the
  filesystem is reading and answering requests on a `/dev/fuse` descriptor;
  performing the mount is the step that needs authorization. Kernel docs say
  unprivileged FUSE mounts go through the setuid `fusermount` helper
  ([FUSE docs](https://docs.kernel.org/filesystems/fuse/fuse.html)), which
  `no-new-privileges` defeats. The alternatives are a mount delegated to the
  driver or another privileged helper that hands the workload side a finished
  mount, or a user + mount namespace created at bootstrap, before Landlock is
  applied. Whether the supervisor can then serve with no added capability is
  an **inference** for the spike to confirm. Vendor statements such as
  Archil's "root, and `CAP_SYS_ADMIN`" describe that client's packaging, not
  a floor for every FUSE daemon. Each option is a labeled deployment change,
  per driver.

## Ranked next experiments

No implementation is proposed yet. Each item states what would falsify it.

### 1. Near-term: faster seccomp + memfd, Landlock retained

- **1a. Reshape dispatch on the single listener.** Two listeners are
  impossible (`EBUSY`; see
  [`seccomp(2)`](https://man7.org/linux/man-pages/man2/seccomp.2.html) and
  `has_duplicate_listener` in
  [`kernel/seccomp.c`](https://github.com/torvalds/linux/blob/master/kernel/seccomp.c)).
  The wakeup flag is also per listener, not per syscall. Test instead: one
  receiver that only classifies, answers ordinary opens inline, and hands every
  potentially blocking notification to workers, with the wakeup hint on.
  Hypothesis: the measured tail regressions came from blocking work on the
  woken CPU. *Falsified if* p99 for 4- and 16-thread opens or `tcp-connect`
  still regresses against the no-hint baseline.
- **1b. Minimal ordinary-open handler.** Measure each step of the continue
  path (receive, prefix read, respond). *Falsified if* handler work is under
  ~10% of the round trip, which current data suggests (about 2 µs of 17).
- **1c. Cache one sealed memfd per file revision**, reopening per open for an
  independent description (a `dup` would share the offset). *Falsified if*
  provider-open cost does not drop, or if any test shows shared offsets or
  cross-revision content.
- **1d. Scalar pre-filtering.** Count how many real-application opens carry
  flags the provider handler always refuses (`O_DIRECTORY`, `O_PATH`, write
  modes). If large, evaluate letting those run natively. *Falsified if* the
  share is small, or if native handling changes an errno a provider path must
  return.

Keep notification-ID validation, cancellation handling, and task identity
checks in every variant. Do not cache path classification by pointer.

### 2. Medium-term: runtime-private synthetic filesystem spike (case C1)

A throwaway prototype outside production code, answering in order:
(i) can a capability-free bootstrap obtain the mount on Docker, Podman,
Kubernetes, and the VM driver, and at what privilege cost; (ii) warm and cold
provider-open cost with zero-message opens; (iii) update, open-descriptor,
read-only `mmap`, and `noexec` behavior; (iv) Landlock rules over the mount.
*Falsified if* no driver can provide the mount without privileges the project
will not grant, or if warm provider opens are not clearly cheaper than the
best result from experiment 1.

### 3. Separate track: durable workspace backend plugins

Define the contract first (single writer or shared; durability point; what a
snapshot includes), then evaluate one FUSE-backed candidate against it.
*Falsified as a near-term item if* the mount privilege question from
experiment 2 has no acceptable answer, since the mounted interface of every
candidate reviewed needs a comparable mount. The pi-durable-disk handoff model
(single holder, generation, release before migration) is a reference for the
single-writer form of the contract.

### 4. Scoped redesign studies, not experiments yet

gVisor with a custom gofer and synthetic config files; VM-internal delivery
for the VM driver. Each needs its own proposal covering the broker rewrite and
the in-sandbox trust split.

### Benchmark matrix for any of the above

| Dimension | Cases |
|---|---|
| Opener threads | 1, 4, 16, and mixed (openers running beside TCP connects) |
| Paths | Ordinary files; real provider paths, warm and cold; missing provider path; write-mode and `openat2` opens |
| Application level | Import-heavy Python start, Node start, a small build, dynamic-loader-heavy exec |
| Metadata-heavy | `stat` and directory walks over a large tree; `git status` |
| Updates | Provider revision change under concurrent readers; descriptor held across update |
| Workspace (track 3 only) | Snapshot and restore time; SQLite in rollback and WAL modes, single and multiple mounts; crash before and after `fsync` |
| Method | The existing paired nine-trial Docker method and the seccomp harness; p50, p99, throughput |

### Success criteria

These are thresholds to judge results against, not predictions.

- Ordinary open/close paired overhead against plain Docker returns near the
  pre-PR level (+12.5%), or the remaining gap is explained by measurement.
- No p99 regression against the current default for 4- and 16-thread opens,
  `tcp-connect`, and `tcp-stream`.
- Provider files keep today's guarantees: read-only, atomic revision switch,
  fail closed, no content visible to a workload outside policy.
- No new privilege in the workload's own security context.
- Sandbox E2E path passes, per `AGENTS.md`.

## Unknowns that matter

- Whether any reviewed shared filesystem is safe for concurrent SQLite WAL
  access from several mounts. Archil and Tensorlake document behavior that
  makes it unsafe by default; LayerFS restricts its own Store to one kernel
  and does not address a database inside a workspace; AgentFS and TiDB do not
  say.
- Whether the user's kernel-hook requirement admits a kernel VFS hook or means
  seccomp user notification specifically. Cases C1, D, and E depend on it.
- The mechanism behind boat/Box restore, and Tensorlake's mount mechanism,
  beyond author statements.
- Whether a capability-free bootstrap can obtain a FUSE mount under each
  driver's default security profile.
- The real cost of a warm FUSE open with zero-message opens on our kernel.
- The Landlock ABI version on the benchmark host's 7.0 kernel, and whether its
  namespace rules are available there.
- Whether the measured wakeup-hint regressions are inherent or an artifact of
  the current dispatch shape.

## Bookmark inventory

All posts were fetched 2026-11-16. "Partial" means only the first ~280
characters were readable; "full" means the post fit. No post's media was
readable.

### Durable volumes and shared workspaces

| Post | Access | Primary source found | Note |
|---|---|---|---|
| [@diptanu 2026-07-20](https://x.com/diptanu/status/2079275585575305308), Tensorlake volumes on E2B/Daytona/Modal | Partial | [Tensorlake docs](https://docs.tensorlake.ai/filesystems/introduction.md) | FUSE/FSKit detail is bookmark-only |
| [@diptanu 2026-09-24](https://x.com/diptanu/status/2103143890132086816), versioned FS independent of sandbox | Partial | Same | "FUSE mounts" is in the visible text: author claim |
| [@diptanu 2026-07-31](https://x.com/diptanu/status/2083056253228695762), shared CI caches | Partial | Same | Author claim |
| [@siddontang 2026-10-05](https://x.com/siddontang/status/2107135890690892117), Daytona mounts TiDB FS | Partial | [Daytona docs](https://www.daytona.io/docs/en/mount-external-storage/) | Verified |
| [@siddontang 2026-10-01](https://x.com/siddontang/status/2105526277193249161), persistent workspace | Full | [PingCAP page](https://www.pingcap.com/tidb/tidb-cloud-filesystem/) | Marketing-level |
| [@siddontang 2026-10-12](https://x.com/siddontang/status/2109718441867542737), one-shot exec | Partial | [drive9 PR #1022](https://github.com/mem9-ai/drive9/pull/1022) | Product-to-repo match uncertain |
| [@siddontang 2026-10-06](https://x.com/siddontang/status/2107518691105796206), progress across sessions | Full | PingCAP page | Marketing-level |
| [@MiguelriosEN 2026-10-21](https://x.com/MiguelriosEN/status/2113016687255494948), pi-durable-disk | Partial | [AgentRun extensions page](https://agentrun.ai/extensions/runs-anywhere); [Parcha-ai/agentrun](https://github.com/Parcha-ai/agentrun); [Archil docs](https://docs.archil.com/details/consistency.md) | Verified from the page: Archil-only in this release, exclusive claim with fencing, no sandboxing. WASM-to-Modal move is bookmark-only |
| [@jhleath 2026-09-08](https://x.com/jhleath/status/2097420953051619559), shared FS as agent memory | Partial | [Archil sharing docs](https://docs.archil.com/concepts/sharing-disks.md) | Opinion |
| [@jhleath 2026-10-19](https://x.com/jhleath/status/2112198618921030073), data-oriented sandboxes | Partial | None needed | Opinion |
| [@jhleath 2026-04-18](https://x.com/jhleath/status/2045515524512387436), Archil serverless execution | Full | [Archil docs](https://docs.archil.com/compute/serverless-execution.md) | Not reviewed in depth |

### Snapshots, branching, storage internals

| Post | Access | Primary source found | Note |
|---|---|---|---|
| [@diptanu 2026-06-18](https://x.com/diptanu/status/2067740028034515418), block vs dedup storage | Partial | None for the numbers | 2–4× is author claim |
| [@diptanu 2026-03-27](https://x.com/diptanu/status/2037580914386145300), CoW snapshots and scheduling | Partial | [Tensorlake snapshots](https://docs.tensorlake.ai/sandboxes/snapshots.md) | Author claim |
| [@diptanu 2026-06-11](https://x.com/diptanu/status/2065071669157429683), snapshot-aware scheduling | Partial | None | Author claim |
| [@AniC_dev 2026-07-13](https://x.com/AniC_dev/status/2076796375803609278), Box fork | Partial | [boat docs](https://docs.boat.dev/snapshots) | FUSE metadata-first restore is bookmark-only |
| [@AniC_dev 2026-07-14](https://x.com/AniC_dev/status/2077154743252578388), Box diff snapshots | Full | Same | Mechanism undocumented |
| [@colemurray 2026-07-20](https://x.com/colemurray/status/2079034256266043487), disk snapshot vs pause | Partial | None needed | Opinion; consistent with boat and Tines choices |
| [@thebsdbox 2026-10-31](https://x.com/thebsdbox/status/2116482355225669660), CoW runtime volumes | Full | Not located | Project unidentified |
| [@rustaceans_rs 2026-10-18](https://x.com/rustaceans_rs/status/2111873467180015848), LayerFS | Full | [LayerFS repo](https://github.com/Ephemeral-AI-Lab/layerfs); [platform docs](https://layerfs.ai/docs/platform/) | Verified identity; single-kernel, local store, `synchronous=OFF` |
| [@yifanxu_ephai 2026-09-09](https://x.com/yifanxu_ephai/status/2097770060765069391), LayerFS vs Btrfs | Partial | Same | Ratio differs from README |
| [@glcst 2026-01-12](https://x.com/glcst/status/2010780029345534310), AgentFS | Partial | [AgentFS repo](https://github.com/tursodatabase/agentfs) | Verified |
| [@c0ngwang 2026-09-16](https://x.com/c0ngwang/status/2100262270165266558), Sandlock deferred commit | Partial | [Sandlock repo](https://github.com/multikernel/sandlock) | Verified model |
| [@c0ngwang 2026-09-27](https://x.com/c0ngwang/status/2104077430948610546), Sandlock confinement | Partial | Same | Symlink detail bookmark-only |
| [@pierrecomputer 2026-09-03](https://x.com/pierrecomputer/status/2095552719683489951), Git as state | Full | [code.storage guide](https://code.storage/docs/guides/resume-sandbox-work) | Reachable; not reviewed in depth |
| [@ovaistariq 2025-12-20](https://x.com/ovaistariq/status/2002265742813622595), Tigris snapshots | Full | [Tigris docs](https://www.tigrisdata.com/docs/buckets/snapshots-and-forks/); quoted [Replit article](https://blog.replit.com/inside-replits-snapshot-engine) | Reachable; object-store level, not reviewed in depth |

### Mounts, local mechanics, adjacent

| Post | Access | Primary source found | Note |
|---|---|---|---|
| [@damian_b 2026-10-14](https://x.com/damian_b/status/2110438081417658507), virtiofs | Full; thread and image not readable | [Kernel virtiofs docs](https://docs.kernel.org/filesystems/virtiofs.html) | Verified from kernel docs instead |
| [@shayonj 2026-10-03](https://x.com/shayonj/status/2106398808296792492), gVisor and Tines | Partial | [Tines article](https://www.shayon.dev/post/2026/283/versioned-filesystem-for-disposable-sandboxes/) | Verified |
| [@iximiuz 2026-04-12](https://x.com/iximiuz/status/2043368804861038827), `sbx` mounts | Partial | Not pursued | Low relevance |
| [@iximiuz 2025-09-12](https://x.com/iximiuz/status/1966549769339248845), container from namespaces | Full | [Tutorial](https://labs.iximiuz.com/tutorials/container-filesystem-from-scratch) | Background for mount-namespace views |
| [@rustaceans_rs 2026-09-04](https://x.com/rustaceans_rs/status/2095733329656000575), Btrfs worktrees | Full | Not located | Low relevance |
| [@dcolascione 2026-07-13](https://x.com/dcolascione/status/2076803943686959517), reflinks and atime pruning | Partial | [Fork of sccache](https://github.com/dcolascione/sccache) | Low relevance |
| [@jespinog 2026-04-25](https://x.com/jespinog/status/2048036619534369203), ZFS internals | Partial | Not pursued | Background |
| [@banteg 2026-01-04](https://x.com/banteg/status/2007748646230733139), shared Docker volumes for auth | Full | [banteg/agents](https://github.com/banteg/agents) | An example of what the user excludes for config |
| [@_orcaman 2026-09-24](https://x.com/_orcaman/status/2103138149329231932), cross-tenant storage escape | Partial | Not located | Unverified author claim; a reminder that shared disks need their own isolation |
| [@MarcJBrooker 2025-11-17](https://x.com/MarcJBrooker/status/1990467764629483541), shared disks vs databases | Full | None needed | Opinion |

### Virtual filesystems as agent interfaces (not transparent enforcement)

| Post | Access | Primary source found | Note |
|---|---|---|---|
| [@zechengzh 2026-10-20](https://x.com/zechengzh/status/2112596868698136924), AgentVFS | Partial | [agentvfs.org](https://agentvfs.org/) | Agent interface, not a POSIX mount contract |
| [@hwchase17 2026-08-16](https://x.com/hwchase17/status/2089029054611837324), deepagents backends | Partial | Not pursued | Tool-level API |
| [@michael_chomsky 2026-04-08](https://x.com/michael_chomsky/status/2041675652676644998), shared FS across tiers | Partial | None | Opinion |
| [@gakonst 2026-11-11](https://x.com/gakonst/status/2120633025344278636), virtualized bash and FS | Full | None | Opinion |
| [@can1357 2026-07-16](https://x.com/can1357/status/2077610722121458123), virtual `/dev` tools | Partial | None | Idea |
| [@penberg 2026-01-02](https://x.com/penberg/status/2007174813467701337), AI SDK + just-bash + AgentFS | Full | [Turso article](https://turso.tech/blog/agentfs-just-bash) | SDK path, not the FUSE path |

## Kernel and platform sources used

- [Landlock user documentation](https://docs.kernel.org/userspace-api/landlock.html) (7.4.0-rc3 docs)
- [`seccomp_unotify(2)`](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html) and [`seccomp(2)`](https://man7.org/linux/man-pages/man2/seccomp.2.html)
- [`kernel/seccomp.c`](https://github.com/torvalds/linux/blob/master/kernel/seccomp.c) and [`include/uapi/linux/fuse.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/fuse.h) at torvalds `aebb72744764` (2026-11-15)
- [FUSE](https://docs.kernel.org/filesystems/fuse/fuse.html) and [FUSE passthrough](https://docs.kernel.org/filesystems/fuse/fuse-passthrough.html) (passthrough needs `CAP_SYS_ADMIN` in the daemon)
- [BPF LSM programs](https://docs.kernel.org/bpf/prog_lsm.html)
- [gVisor security model](https://gvisor.dev/docs/architecture_guide/security/), [platforms](https://gvisor.dev/docs/architecture_guide/platforms/)
- [Docker default seccomp profile](https://docs.docker.com/engine/security/seccomp/)
- Host facts read on the benchmark host: kernel `7.0.0-1017-gcp`; active LSMs include `landlock`, `apparmor`, `bpf`; `/dev/fuse` present on the host; `/dev/kvm` absent; `apparmor_restrict_unprivileged_userns=1`.
