// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider files published as real files the workload opens natively.
//!
//! The runtime and the workload share one UID, so file modes cannot keep the
//! workload from changing a provider file. Two mounts of one driver-owned
//! filesystem do:
//!
//! - The **private root**, writable, lies beneath `/.openshell`. The mandatory
//!   Landlock baseline grants the workload no access right there, so through
//!   this path it cannot open, list, create, remove, rename, or truncate
//!   anything. It holds `public/` and `staging/`.
//! - The **public root** is a read-only mount of `public/` at the path the
//!   workload reads. The kernel refuses every write and metadata change made
//!   through it, whatever the caller's UID.
//!
//! What this protects is content and names. Landlock does not mediate
//! `chmod` or `stat`, so the workload, which owns these files too, can change
//! a mode through the private path and can `stat` a name it knows there. A
//! changed mode never grants it access, since Landlock still refuses the
//! open; it can only deny the workload its own files until the next update.
//! The runtime restores the modes it needs before each update, and staged
//! and replaced generations have unpredictable names.
//!
//! A generation is built under `staging/`, which has no public path, and is
//! then exchanged with `public/providers` in one `renameat2` call. The
//! workload therefore sees the previous generation or the next one, never a
//! partial one, and no path exposes a staged or a replaced generation.
//!
//! A file descriptor opened before an update keeps reading the file it
//! opened, for as long as it stays open. A directory descriptor does not get
//! that guarantee: a replaced generation is removed after
//! [`Retention::grace`], which exists so that an open already walking into
//! the published directory when it was exchanged still finds its file.
//!
//! That open also depends on Landlock, because the exchange moves the
//! replaced generation out of `public`, the only part of the store the
//! workload may read. A kernel with the upstream change to Landlock's
//! handling of disconnected directories (CVE-2025-68736) judges the open by
//! the read-only mount it came through and allows it. A kernel without it
//! refuses the open with `EACCES`. The store therefore asks the running
//! kernel, once, before any workload exists: [`NativeStore::open`] puts a
//! throwaway thread under the workload's Landlock layers, has it resolve the
//! published directory, exchanges that generation out, and has it open a
//! file beneath the directory it holds. Only a kernel that allows that open
//! gets native delivery. One that refuses it gets virtual delivery, after
//! the store is proven empty. Nothing is inferred from a kernel version.
//!
//! The public root is the stable parent of the `providers` directory rather
//! than that directory itself: a mount pinned to `providers` would keep
//! showing the inode of the first generation forever.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Write as _};
use std::os::fd::{AsFd, AsRawFd as _, BorrowedFd, OwnedFd};
use std::path::{Component, Path};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use openshell_sandbox_backend::boundary_protocol::ProviderFileStore;
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, RenameFlags, StatVfsMountFlags};

/// The path the workload reads; the parent of the `providers` directory.
pub const PUBLIC_ROOT: &str = "/run/openshell";
/// The hierarchy the mandatory Landlock baseline withholds from the workload.
const PRIVATE_HIERARCHY: &str = ".openshell";
const PUBLIC_DIRECTORY: &CStr = c"public";
const STAGING_DIRECTORY: &CStr = c"staging";
const PROVIDERS_DIRECTORY: &CStr = c"providers";
/// A generation is `<generation>/<provider>/<file>`.
const GENERATION_DEPTH: usize = 3;

const PUBLIC_MODE: Mode = Mode::from_bits_truncate(0o755);
const PRIVATE_DIRECTORY_MODE: Mode = Mode::from_bits_truncate(0o700);
/// The mode an injected provider descriptor reports. The mode protects
/// nothing here: the read-only mount and Landlock keep the content.
const FILE_MODE: Mode = Mode::from_bits_truncate(0o600);

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

/// Whether [`NativeStore::open_roots`] requires the public root to be a
/// read-only mount. Production always does.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PublicMount {
    RequireReadOnly,
    /// Tests and the opt-in performance harness cannot mount a filesystem.
    /// They exercise publication and the open filter, not the mount.
    #[cfg(any(test, feature = "perf-harness"))]
    AnyForTest,
}

/// Whether this kernel lets a confined open finish in a generation that was
/// exchanged out of the public directory while the open was walking it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Capability {
    Qualified,
    /// Landlock refused the open. Native delivery would fail a workload open
    /// caught by an update, so the caller must deliver virtually.
    Unqualified,
}

/// The provider file only the capability probe ever publishes. It holds no
/// provider content and is removed before any workload exists.
const PROBE_FILE: &str = "/run/openshell/providers/openshell-probe/probe";
const PROBE_RELATIVE: &str = "openshell-probe/probe";
const PROBE_CONTENT: &str = "probe";
/// How long either side of the probe waits for the other's single step.
const PROBE_STEP_TIMEOUT: Duration = Duration::from_secs(10);

/// How long, and how much of, replaced generations the store keeps.
#[derive(Clone, Copy, Debug)]
struct Retention {
    /// How long a replaced generation outlives its replacement.
    ///
    /// An open that had already walked into the published directory when it
    /// was exchanged still looks its file up there. Removing the replaced
    /// generation at once would fail that open with `ENOENT` although the
    /// file exists in both generations, which an injected descriptor never
    /// does. A path walk takes microseconds; the grace allows for a
    /// preempted one. Zero removes a replaced generation before `publish`
    /// returns.
    grace: Duration,
    /// Replaced generations kept at once.
    max_generations: usize,
    /// Content bytes of replaced generations kept at once.
    max_bytes: usize,
}

impl Retention {
    /// Eight generations or four of the largest size, whichever is less. A
    /// faster burst of updates waits for the oldest to age out.
    const PRODUCTION: Self = Self {
        grace: Duration::from_secs(1),
        max_generations: 8,
        max_bytes: 4 * crate::provider_files::MAX_TOTAL_BYTES,
    };
}

/// A validated provider-file store.
pub struct NativeStore {
    shared: Arc<Shared>,
    retention: Retention,
}

struct Shared {
    /// The store's `public` directory, through the writable private mount.
    public: OwnedFd,
    /// The store's `staging` directory, which has no public path.
    staging: OwnedFd,
    /// Serializes publications and removals.
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// The files of the published generation, once this run has published
    /// one. An update that asks for exactly these files publishes nothing.
    published: Option<HashMap<String, String>>,
    /// Content bytes of the published generation.
    published_bytes: usize,
    /// Replaced generations still in `staging`.
    retired: Vec<Retired>,
    /// Whether the reaper thread is running.
    reaping: bool,
}

struct Retired {
    name: CString,
    replaced: Instant,
    bytes: usize,
    /// Whether a removal was attempted and failed. The generation stays
    /// counted against the retention bounds until a removal succeeds.
    removal_failed: bool,
}

impl State {
    fn retired_bytes(&self) -> usize {
        self.retired.iter().map(|retired| retired.bytes).sum()
    }
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Remove every retired generation replaced at least `grace` ago. One
    /// that cannot be removed stays in the list, counted, for a later try.
    fn reap(&self, state: &mut State, grace: Duration) {
        let now = Instant::now();
        state.retired.retain_mut(|retired| {
            if now.saturating_duration_since(retired.replaced) < grace {
                return true;
            }
            match remove_entry(self.staging.as_fd(), &retired.name, GENERATION_DEPTH) {
                Ok(()) => false,
                Err(error) => {
                    tracing::debug!(%error, "replaced provider file generation not removed");
                    retired.removal_failed = true;
                    true
                }
            }
        });
    }

    /// The single reaper thread: remove retired generations as their grace
    /// passes, and stop once none is waiting for its first attempt. A
    /// generation whose removal failed is retried by the next publication
    /// instead, so the thread never spins on it.
    fn run_reaper(&self, grace: Duration) {
        loop {
            std::thread::sleep(grace);
            let mut state = self.lock();
            self.reap(&mut state, grace);
            if state.retired.iter().all(|retired| retired.removal_failed) {
                state.reaping = false;
                return;
            }
        }
    }
}

impl NativeStore {
    /// Validate the driver-declared store and publish an empty generation.
    ///
    /// Every check must hold before the caller may stop intercepting
    /// read-only opens:
    ///
    /// - the public root is exactly the path provider files are addressed by;
    /// - the private root lies beneath the real `/.openshell` directory, with
    ///   no symlink on the way;
    /// - `public` and `staging` are real directories on one filesystem, owned
    ///   by this process's UID;
    /// - the public root is the same directory as `public`, on a read-only
    ///   mount, while the private mount is writable;
    /// - the filesystem exchanges two directories atomically, which the
    ///   first, empty publication exercises.
    ///
    /// A store that fails any of them is an error. A store that passes all
    /// of them is then qualified against the running kernel by
    /// [`Self::probe`]. `Ok(None)` means exactly one thing: the store is
    /// valid and proven empty, and this kernel refuses an open caught by an
    /// exchange, so the caller must keep intercepting opens. A probe that
    /// could not complete, or a store it could not leave empty, is an error.
    pub(crate) fn open(config: &ProviderFileStore) -> io::Result<Option<Self>> {
        if config.public_root != Path::new(PUBLIC_ROOT) {
            return Err(invalid(format!(
                "provider file store public root must be {PUBLIC_ROOT}"
            )));
        }
        let private_root = open_private_root(&config.private_root)?;
        Self::open_roots(
            private_root,
            &config.public_root,
            PublicMount::RequireReadOnly,
            Retention::PRODUCTION,
        )?
        .qualify(|store| {
            store.probe(&config.private_root, &config.public_root, || {
                confine_as_workload(&config.public_root)
            })
        })
    }

    /// Keep the store only if `probe` qualifies the kernel.
    ///
    /// Whatever the probe answered, the store must be empty again before the
    /// answer is used: an unqualified kernel gets virtual delivery, which
    /// does not see a relative open of a file left at the provider path.
    fn qualify(
        self,
        probe: impl FnOnce(&Self) -> io::Result<Capability>,
    ) -> io::Result<Option<Self>> {
        let capability = probe(&self)?;
        self.require_empty()?;
        Ok((capability == Capability::Qualified).then_some(self))
    }

    /// Fail unless the store holds one empty published generation and
    /// nothing else.
    fn require_empty(&self) -> io::Result<()> {
        let shared = &self.shared;
        let _state = shared.lock();
        let published = open_directory(&shared.public, PROVIDERS_DIRECTORY)?;
        if entry_names(&shared.public)?.len() != 1
            || !entry_names(&published)?.is_empty()
            || !entry_names(&shared.staging)?.is_empty()
        {
            return Err(io::Error::other(
                "provider file store is not empty after its capability probe",
            ));
        }
        Ok(())
    }

    /// Ask the running kernel whether a confined open survives an exchange.
    ///
    /// Valid only on a freshly opened store, while no workload exists. A
    /// throwaway thread applies `confine`, which in production is the
    /// workload's own Landlock layers; Landlock confines the calling thread
    /// alone, so this runtime stays unconfined. The thread checks that the
    /// private root is closed to it and that it can read a probe file by its
    /// public path, and holds the published directory. This thread then
    /// exchanges that generation out to `staging`, and the confined thread
    /// opens the file again beneath the directory it holds: the state of a
    /// workload open caught mid-walk by an update.
    ///
    /// Success there is [`Capability::Qualified`] and `EACCES` there is
    /// [`Capability::Unqualified`]. Every other outcome is an error: a
    /// confinement that could not be applied or does not hide the private
    /// root, a probe file unreadable before the exchange, a step that timed
    /// out, or a probe generation that could not be removed.
    ///
    /// The confined thread is always joined before this returns. Each of its
    /// waits is bounded by [`PROBE_STEP_TIMEOUT`].
    fn probe(
        &self,
        private_root: &Path,
        public_root: &Path,
        confine: impl FnOnce() -> io::Result<()> + Send,
    ) -> io::Result<Capability> {
        let shared = &self.shared;
        let _state = shared.lock();
        let name = generation_name()?;
        // Exchanging twice restores the empty generation `open_roots`
        // published, so the published state this run tracks stays true.
        let exchange = || {
            rustix::fs::renameat_with(
                &shared.staging,
                &name,
                &shared.public,
                PROVIDERS_DIRECTORY,
                RenameFlags::EXCHANGE,
            )
            .map_err(io::Error::from)
        };
        let remove = || remove_entry(shared.staging.as_fd(), &name, GENERATION_DEPTH);
        let desired = HashMap::from([(PROBE_FILE.to_string(), PROBE_CONTENT.to_string())]);
        if let Err(error) =
            build_generation(&shared.staging, &name, &desired).and_then(|()| exchange())
        {
            let _ = remove();
            return Err(error);
        }
        let mut probe_published = true;
        let outcome = std::thread::scope(|scope| {
            let (pinned, is_pinned) = std::sync::mpsc::channel();
            let (exchanged, is_exchanged) = std::sync::mpsc::channel();
            let reader = std::thread::Builder::new()
                .name("openshell-provider-probe".to_string())
                .spawn_scoped(scope, move || {
                    confined_probe_reader(
                        private_root,
                        public_root,
                        confine,
                        &pinned,
                        &is_exchanged,
                    )
                })?;
            // A reader that failed or stalled never reports; its own result
            // says which, once it is joined.
            let moved = match is_pinned.recv_timeout(PROBE_STEP_TIMEOUT) {
                Ok(()) => exchange().map(|()| probe_published = false),
                Err(_) => Ok(()),
            };
            if !probe_published {
                let _ = exchanged.send(());
            }
            // Dropping the sender ends a reader still waiting for it.
            drop(exchanged);
            let outcome = reader
                .join()
                .map_err(|_| io::Error::other("provider file capability probe panicked"));
            moved?;
            outcome?
        });
        if probe_published {
            exchange()?;
        }
        remove()?;
        outcome
    }

    /// Lay out and open a store in `root` without a read-only public mount.
    ///
    /// The workload reads through `root/public` itself. Nothing in the
    /// production path reaches this constructor.
    #[cfg(any(test, feature = "perf-harness"))]
    pub(crate) fn open_unmounted_for_test(root: &Path) -> io::Result<Self> {
        for (name, mode) in [("public", PUBLIC_MODE), ("staging", PRIVATE_DIRECTORY_MODE)] {
            match rustix::fs::mkdir(root.join(name), mode) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let private_root = rustix::fs::open(
            root,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Self::open_roots(
            private_root,
            &root.join("public"),
            PublicMount::AnyForTest,
            Retention::PRODUCTION,
        )
    }

    fn open_roots(
        private_root: OwnedFd,
        public_root: &Path,
        public_mount: PublicMount,
        retention: Retention,
    ) -> io::Result<Self> {
        let public = open_own_directory(&private_root, PUBLIC_DIRECTORY)?;
        let staging = open_own_directory(&private_root, STAGING_DIRECTORY)?;
        let public_stat = rustix::fs::fstat(&public)?;
        let staging_stat = rustix::fs::fstat(&staging)?;
        if public_stat.st_dev != staging_stat.st_dev {
            return Err(invalid(
                "provider file store directories are on different filesystems",
            ));
        }
        if rustix::fs::fstatvfs(&public)?
            .f_flag
            .contains(StatVfsMountFlags::RDONLY)
        {
            return Err(invalid("provider file store private mount is read-only"));
        }
        // An earlier run's workload may have changed these modes.
        rustix::fs::fchmod(&public, PUBLIC_MODE)?;
        rustix::fs::fchmod(&staging, PRIVATE_DIRECTORY_MODE)?;
        // The workload reads through this path. It must show the directory
        // the runtime publishes into, and its mount must refuse writes.
        let exposed = rustix::fs::open(
            public_root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let exposed_stat = rustix::fs::fstat(&exposed)?;
        if (exposed_stat.st_dev, exposed_stat.st_ino) != (public_stat.st_dev, public_stat.st_ino) {
            return Err(invalid(
                "provider file store public root is not the store's public directory",
            ));
        }
        if public_mount == PublicMount::RequireReadOnly
            && !rustix::fs::fstatvfs(&exposed)?
                .f_flag
                .contains(StatVfsMountFlags::RDONLY)
        {
            return Err(invalid(
                "provider file store public root is not a read-only mount",
            ));
        }
        drop(exposed);
        // Only the generation directory may ever be visible to the workload.
        for name in entry_names(&public)? {
            if name.as_c_str() != PROVIDERS_DIRECTORY {
                return Err(invalid(
                    "provider file store public directory holds an unexpected entry",
                ));
            }
        }
        let store = Self {
            shared: Arc::new(Shared {
                public,
                staging,
                state: Mutex::default(),
            }),
            retention,
        };
        // No workload exists yet, so nothing can be walking the store:
        // discard whatever an earlier run left, at once, and prove the
        // exchange works. Stale provider content that cannot be removed
        // must not stay behind a path the workload will be able to read.
        store.clear_staging()?;
        store.publish_with(
            &HashMap::new(),
            Retention {
                grace: Duration::ZERO,
                ..retention
            },
        )?;
        Ok(store)
    }

    /// Replace the published generation with exactly `desired`.
    ///
    /// The caller has validated `desired`. On error the previous generation
    /// stays published, untouched.
    ///
    /// An update equal to the published generation exchanges nothing and
    /// retains nothing, so repeating one never waits on the retention bounds.
    /// It still republishes if the workload changed a published mode.
    ///
    /// Updates that arrive faster than replaced generations age out wait,
    /// for at most the grace, until the oldest can be removed. If the
    /// retention bounds still cannot be met, because a removal failed, the
    /// update is refused before anything is written.
    pub(crate) fn publish(&self, desired: &HashMap<String, String>) -> io::Result<()> {
        self.publish_with(desired, self.retention)
    }

    fn publish_with(
        &self,
        desired: &HashMap<String, String>,
        retention: Retention,
    ) -> io::Result<()> {
        let shared = &self.shared;
        let mut state = shared.lock();
        // The workload owns these directories too and can change their mode
        // through the private path, which Landlock does not mediate. Restore
        // the modes the runtime needs; the content is beyond its reach.
        rustix::fs::fchmod(&shared.public, PUBLIC_MODE)?;
        rustix::fs::fchmod(&shared.staging, PRIVATE_DIRECTORY_MODE)?;
        if state.published.as_ref() == Some(desired)
            && published_generation_is_intact(&shared.public, desired).unwrap_or(false)
        {
            return Ok(());
        }
        Self::make_room(shared, &mut state, retention)?;

        // Unpredictable, so the workload cannot `stat` a staged or replaced
        // generation through the private path.
        let name = generation_name()?;
        let discard = |error: io::Error| {
            let _ = remove_entry(shared.staging.as_fd(), &name, GENERATION_DEPTH);
            error
        };
        build_generation(&shared.staging, &name, desired).map_err(discard)?;
        let bytes = desired.values().map(String::len).sum::<usize>();
        // Moving a directory to another parent needs write permission on
        // the directory itself. Restore it on the published generation, whose
        // mode the workload may have cleared; anything that is not this
        // process's own directory is exchanged as it is.
        let _ = restore_directory_access(shared.public.as_fd(), PROVIDERS_DIRECTORY);
        match rustix::fs::renameat_with(
            &shared.staging,
            &name,
            &shared.public,
            PROVIDERS_DIRECTORY,
            RenameFlags::EXCHANGE,
        ) {
            // The staged name now holds the generation this one replaced.
            Ok(()) => {}
            // Nothing was published yet, so there is nothing to exchange.
            Err(rustix::io::Errno::NOENT) => {
                rustix::fs::renameat(&shared.staging, &name, &shared.public, PROVIDERS_DIRECTORY)
                    .map_err(|error| discard(error.into()))?;
                state.published_bytes = bytes;
                state.published = Some(desired.clone());
                return Ok(());
            }
            Err(error) => return Err(discard(error.into())),
        }
        let replaced_bytes = std::mem::replace(&mut state.published_bytes, bytes);
        state.published = Some(desired.clone());
        state.retired.push(Retired {
            name,
            replaced: Instant::now(),
            bytes: replaced_bytes,
            removal_failed: false,
        });
        if retention.grace.is_zero() {
            shared.reap(&mut state, retention.grace);
        } else if !state.reaping {
            // If the thread cannot start, the next publication reaps.
            let reaper = Arc::clone(shared);
            state.reaping = std::thread::Builder::new()
                .name("openshell-provider-files".to_string())
                .spawn(move || reaper.run_reaper(retention.grace))
                .is_ok();
        }
        Ok(())
    }

    /// Ensure the generation about to be replaced can be retained within the
    /// bounds, before anything is written.
    fn make_room(shared: &Shared, state: &mut State, retention: Retention) -> io::Result<()> {
        // With no grace the replaced generation is removed before `publish`
        // returns and is never retained.
        if retention.grace.is_zero() {
            shared.reap(state, retention.grace);
            return Ok(());
        }
        let fits = |state: &State| {
            state.retired.len() < retention.max_generations
                && state.retired_bytes() + state.published_bytes <= retention.max_bytes
        };
        loop {
            shared.reap(state, retention.grace);
            if fits(state) {
                return Ok(());
            }
            // Wait for the next generation to age out, holding the lock so
            // no other publication overtakes this one. The reaper thread
            // waits on the same lock; this thread reaps in its place. The
            // waits add up to at most one grace.
            // A generation that aged out between the reap above and this
            // reading of the clock waits no time and is reaped next.
            let now = Instant::now();
            let next = state
                .retired
                .iter()
                .filter(|retired| !retired.removal_failed)
                .map(|retired| {
                    retention
                        .grace
                        .saturating_sub(now.saturating_duration_since(retired.replaced))
                })
                .min();
            let Some(wait) = next else {
                // Everything retained has aged out and could not be removed.
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "provider file store holds replaced generations it cannot remove",
                ));
            };
            std::thread::sleep(wait);
        }
    }

    /// Remove everything in `staging`. Only valid while no workload exists.
    fn clear_staging(&self) -> io::Result<()> {
        let shared = &self.shared;
        let _state = shared.lock();
        for name in entry_names(&shared.staging)? {
            remove_entry(shared.staging.as_fd(), &name, GENERATION_DEPTH)?;
        }
        Ok(())
    }
}

fn generation_name() -> io::Result<CString> {
    let random = openshell_crypto::random_bytes::<16>()
        .map_err(|error| io::Error::other(format!("name provider file generation: {error}")))?;
    CString::new(format!("generation-{}", hex::encode(random)))
        .map_err(|_| invalid("generation name contains NUL"))
}

/// Confine the calling thread as a workload is confined: the mandatory
/// baseline, then a filesystem policy that lists only the public root, which
/// is the grant native delivery adds to a user policy. Passing both layers
/// implies passing the baseline alone.
fn confine_as_workload(public_root: &Path) -> io::Result<()> {
    use openshell_core::policy::{
        FilesystemPolicy, LandlockCompatibility, LandlockPolicy, NetworkPolicy, ProcessPolicy,
        SandboxPolicy,
    };
    let policy = SandboxPolicy {
        version: 1,
        filesystem: FilesystemPolicy {
            read_only: vec![public_root.to_path_buf()],
            read_write: Vec::new(),
            include_workdir: false,
        },
        network: NetworkPolicy::default(),
        landlock: LandlockPolicy {
            compatibility: LandlockCompatibility::HardRequirement,
        },
        process: ProcessPolicy::default(),
    };
    let confined = |error: miette::Report| {
        io::Error::other(format!("confine provider file capability probe: {error}"))
    };
    let prepared =
        crate::sandbox::linux::prepare_capability_free(&policy, None).map_err(confined)?;
    crate::sandbox::linux::enforce_landlock(prepared).map_err(confined)
}

/// The confined half of [`NativeStore::probe`].
fn confined_probe_reader(
    private_root: &Path,
    public_root: &Path,
    confine: impl FnOnce() -> io::Result<()>,
    pinned: &std::sync::mpsc::Sender<()>,
    exchanged: &std::sync::mpsc::Receiver<()>,
) -> io::Result<Capability> {
    let incomplete = |what: &str| {
        io::Error::other(format!(
            "provider file capability probe is incomplete: {what}"
        ))
    };
    confine()?;
    for hidden in [private_root.to_path_buf(), private_root.join("staging")] {
        match File::open(&hidden) {
            Err(error) if error.raw_os_error() == Some(libc::EACCES) => {}
            Ok(_) => return Err(incomplete("its confinement does not hide the private root")),
            Err(error) => return Err(error),
        }
    }
    let read = |directory: &OwnedFd| -> io::Result<()> {
        let file = rustix::fs::openat(
            directory,
            PROBE_RELATIVE,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let mut content = String::new();
        io::Read::read_to_string(&mut File::from(file), &mut content)?;
        if content != PROBE_CONTENT {
            return Err(incomplete("the probe file has unexpected content"));
        }
        Ok(())
    };
    let directory = rustix::fs::open(
        public_root.join("providers"),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    // The grant itself must work, or a refusal below would mean nothing.
    read(&directory)?;
    pinned
        .send(())
        .map_err(|_| incomplete("the exchange was abandoned"))?;
    exchanged
        .recv_timeout(PROBE_STEP_TIMEOUT)
        .map_err(|_| incomplete("the exchange did not happen"))?;
    match read(&directory) {
        Ok(()) => Ok(Capability::Qualified),
        Err(error) if error.raw_os_error() == Some(libc::EACCES) => Ok(Capability::Unqualified),
        Err(error) => Err(error),
    }
}

/// Open the private root by walking from `/` without following a symlink,
/// requiring it to lie strictly beneath the real `/.openshell` directory.
fn open_private_root(path: &Path) -> io::Result<OwnedFd> {
    let mut components = path.components();
    if components.next() != Some(Component::RootDir)
        || components.next() != Some(Component::Normal(PRIVATE_HIERARCHY.as_ref()))
    {
        return Err(invalid(
            "provider file store private root must lie beneath /.openshell",
        ));
    }
    let mut directory = rustix::fs::open(
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    directory = rustix::fs::openat(
        &directory,
        PRIVATE_HIERARCHY,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut depth = 0;
    for component in components {
        let Component::Normal(name) = component else {
            return Err(invalid(
                "provider file store private root must be a normalized path",
            ));
        };
        directory = rustix::fs::openat(
            &directory,
            name,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        depth += 1;
    }
    if depth == 0 {
        return Err(invalid(
            "provider file store private root must lie beneath /.openshell",
        ));
    }
    Ok(directory)
}

/// Open a real directory by name, never a symlink to one.
fn open_directory(parent: impl AsFd, name: &CStr) -> io::Result<OwnedFd> {
    Ok(rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

/// Open a real directory this process owns, restoring access first if its
/// mode was cleared.
fn open_own_directory(parent: &OwnedFd, name: &CStr) -> io::Result<OwnedFd> {
    let directory = match open_directory(parent, name) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            restore_directory_access(parent.as_fd(), name)?;
            open_directory(parent, name)?
        }
        Err(error) => return Err(error),
    };
    if rustix::fs::fstat(&directory)?.st_uid != rustix::process::geteuid().as_raw() {
        return Err(invalid(
            "provider file store directories are not owned by the sandbox identity",
        ));
    }
    Ok(directory)
}

fn entry_names(directory: impl AsFd) -> io::Result<Vec<CString>> {
    let mut names = Vec::new();
    for entry in Dir::read_from(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        if name != c"." && name != c".." {
            names.push(name.to_owned());
        }
    }
    Ok(names)
}

fn create_directory(parent: impl AsFd, name: &CStr) -> io::Result<OwnedFd> {
    rustix::fs::mkdirat(&parent, name, PRIVATE_DIRECTORY_MODE)?;
    let directory = open_directory(&parent, name)?;
    // Independent of the process umask.
    rustix::fs::fchmod(&directory, PRIVATE_DIRECTORY_MODE)?;
    Ok(directory)
}

/// Write one complete generation as `staging/<name>/<provider>/<file>`.
fn build_generation(
    staging: &OwnedFd,
    name: &CStr,
    desired: &HashMap<String, String>,
) -> io::Result<()> {
    let generation = create_directory(staging, name)?;
    let mut providers: HashMap<&str, OwnedFd> = HashMap::new();
    for (path, content) in desired {
        let (provider, file_name) = crate::provider_files::provider_and_file(path)?;
        let directory = match providers.entry(provider) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let provider = CString::new(provider).map_err(|_| invalid("provider name"))?;
                entry.insert(create_directory(&generation, &provider)?)
            }
        };
        let file_name = CString::new(file_name).map_err(|_| invalid("provider file name"))?;
        let mut file = File::from(rustix::fs::openat(
            &*directory,
            &file_name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            FILE_MODE,
        )?);
        file.write_all(content.as_bytes())?;
        // Independent of the process umask.
        rustix::fs::fchmod(&file, FILE_MODE)?;
    }
    Ok(())
}

/// Whether the published generation still holds `desired` with the modes it
/// was built with.
///
/// The workload cannot change published content or names, but it can change
/// a mode through the private path. A generation with a changed mode is
/// replaced rather than kept, so an update always ends such a self-inflicted
/// denial.
fn published_generation_is_intact(
    public: &OwnedFd,
    desired: &HashMap<String, String>,
) -> io::Result<bool> {
    let has_mode = |stat: &rustix::fs::Stat, kind: FileType, mode: Mode| {
        FileType::from_raw_mode(stat.st_mode) == kind && Mode::from_raw_mode(stat.st_mode) == mode
    };
    let generation = open_directory(public, PROVIDERS_DIRECTORY)?;
    if !has_mode(
        &rustix::fs::fstat(&generation)?,
        FileType::Directory,
        PRIVATE_DIRECTORY_MODE,
    ) {
        return Ok(false);
    }
    let mut providers: HashMap<&str, OwnedFd> = HashMap::new();
    for (path, content) in desired {
        let (provider, file_name) = crate::provider_files::provider_and_file(path)?;
        let directory = match providers.entry(provider) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let provider = CString::new(provider).map_err(|_| invalid("provider name"))?;
                let directory = open_directory(&generation, &provider)?;
                if !has_mode(
                    &rustix::fs::fstat(&directory)?,
                    FileType::Directory,
                    PRIVATE_DIRECTORY_MODE,
                ) {
                    return Ok(false);
                }
                entry.insert(directory)
            }
        };
        let file_name = CString::new(file_name).map_err(|_| invalid("provider file name"))?;
        let stat = rustix::fs::statat(&*directory, &file_name, AtFlags::SYMLINK_NOFOLLOW)?;
        if !has_mode(&stat, FileType::RegularFile, FILE_MODE)
            || u64::try_from(stat.st_size).ok() != u64::try_from(content.len()).ok()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Remove `name` and, if it is a directory, everything beneath it, without
/// following a symlink and without descending more than `depth` directories.
fn remove_entry(parent: BorrowedFd<'_>, name: &CStr, depth: usize) -> io::Result<()> {
    match rustix::fs::unlinkat(parent, name, AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => return Ok(()),
        // Linux reports a directory as EISDIR; POSIX allows EPERM.
        Err(rustix::io::Errno::ISDIR | rustix::io::Errno::PERM) => {}
        Err(error) => return Err(error.into()),
    }
    if depth == 0 {
        return Err(invalid("provider file generation is nested too deeply"));
    }
    let directory = match open_directory(parent, name) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            restore_directory_access(parent, name)?;
            open_directory(parent, name)?
        }
        Err(error) => return Err(error),
    };
    // Removing entries needs write and search permission on the directory.
    rustix::fs::fchmod(&directory, PRIVATE_DIRECTORY_MODE)?;
    for child in entry_names(&directory)? {
        remove_entry(directory.as_fd(), &child, depth - 1)?;
    }
    drop(directory);
    Ok(rustix::fs::unlinkat(parent, name, AtFlags::REMOVEDIR)?)
}

/// Give this process back access to its own directory whose mode was
/// cleared, addressing the directory itself rather than a path to it.
fn restore_directory_access(parent: BorrowedFd<'_>, name: &CStr) -> io::Result<()> {
    let handle = rustix::fs::openat(
        parent,
        name,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let stat = rustix::fs::fstat(&handle)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != rustix::process::geteuid().as_raw()
    {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }
    // An O_PATH descriptor cannot be passed to fchmod; its procfs link names
    // the same inode.
    Ok(rustix::fs::chmod(
        format!("/proc/self/fd/{}", handle.as_raw_fd()),
        PRIVATE_DIRECTORY_MODE,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::PathBuf;

    const ACME_CONFIG: &str = "/run/openshell/providers/acme/client.toml";
    const ACME_KEY: &str = "/run/openshell/providers/acme/key.pem";
    const OTHER_TOKEN: &str = "/run/openshell/providers/other/token";
    /// Replaced generations removed before `publish` returns.
    const IMMEDIATE: Retention = Retention {
        grace: Duration::ZERO,
        ..Retention::PRODUCTION
    };

    /// A store laid out as the driver stages it. The test reads through the
    /// `public` directory itself, which is the directory a read-only mount
    /// would show.
    struct TestStore {
        _directory: tempfile::TempDir,
        root: PathBuf,
    }

    impl TestStore {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().to_path_buf();
            for (name, mode) in [("public", 0o755), ("staging", 0o700)] {
                std::fs::create_dir(root.join(name)).unwrap();
                std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(mode))
                    .unwrap();
            }
            Self {
                _directory: directory,
                root,
            }
        }

        fn public(&self) -> PathBuf {
            self.root.join("public")
        }

        fn staging(&self) -> PathBuf {
            self.root.join("staging")
        }

        fn providers(&self) -> PathBuf {
            self.public().join("providers")
        }

        fn root_fd(&self) -> OwnedFd {
            rustix::fs::open(
                &self.root,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap()
        }

        /// Open with replaced generations removed before `publish` returns,
        /// so a test can inspect `staging` right away.
        fn open(&self) -> io::Result<NativeStore> {
            self.open_with_grace(Duration::ZERO)
        }

        fn open_with_grace(&self, grace: Duration) -> io::Result<NativeStore> {
            self.open_retaining(Retention {
                grace,
                ..Retention::PRODUCTION
            })
        }

        fn open_retaining(&self, retention: Retention) -> io::Result<NativeStore> {
            NativeStore::open_roots(
                self.root_fd(),
                &self.public(),
                PublicMount::AnyForTest,
                retention,
            )
        }

        fn read(&self, provider_path: &str) -> io::Result<String> {
            let relative = provider_path
                .strip_prefix("/run/openshell/")
                .expect("provider path");
            std::fs::read_to_string(self.public().join(relative))
        }
    }

    fn files(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(path, content)| ((*path).to_string(), (*content).to_string()))
            .collect()
    }

    fn names(directory: &Path) -> Vec<String> {
        let mut names = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    #[test]
    fn opening_publishes_an_empty_generation_and_clears_an_earlier_run() {
        let layout = TestStore::new();
        // An earlier run's generation and an interrupted staging directory.
        std::fs::create_dir_all(layout.providers().join("stale")).unwrap();
        std::fs::write(layout.providers().join("stale/secret"), "old").unwrap();
        std::fs::create_dir_all(layout.staging().join("generation-9-dead/acme")).unwrap();
        std::fs::write(layout.staging().join("generation-9-dead/acme/key"), "x").unwrap();

        let _store = layout.open().unwrap();
        assert_eq!(names(&layout.public()), ["providers"]);
        assert!(names(&layout.providers()).is_empty());
        assert!(names(&layout.staging()).is_empty());
    }

    #[test]
    fn attach_update_and_detach_replace_the_whole_generation() {
        let layout = TestStore::new();
        let store = layout.open().unwrap();

        store
            .publish(&files(&[
                (ACME_CONFIG, "version = 1\n"),
                (ACME_KEY, "key-1"),
            ]))
            .unwrap();
        assert_eq!(layout.read(ACME_CONFIG).unwrap(), "version = 1\n");
        assert_eq!(layout.read(ACME_KEY).unwrap(), "key-1");
        let metadata = std::fs::metadata(layout.providers().join("acme/key.pem")).unwrap();
        // The mode an injected provider descriptor reports.
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);

        // A descriptor opened now keeps this generation's content.
        let mut held = File::open(layout.providers().join("acme/key.pem")).unwrap();

        // Update one provider, attach another.
        store
            .publish(&files(&[
                (ACME_CONFIG, "version = 2\n"),
                (ACME_KEY, "key-2"),
                (OTHER_TOKEN, "token"),
            ]))
            .unwrap();
        assert_eq!(layout.read(ACME_CONFIG).unwrap(), "version = 2\n");
        assert_eq!(layout.read(ACME_KEY).unwrap(), "key-2");
        assert_eq!(layout.read(OTHER_TOKEN).unwrap(), "token");

        // Detach the first provider: its files are gone, not left behind.
        store.publish(&files(&[(OTHER_TOKEN, "token")])).unwrap();
        assert_eq!(names(&layout.providers()), ["other"]);
        assert_eq!(
            layout.read(ACME_KEY).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );

        // Detach everything.
        store.publish(&HashMap::new()).unwrap();
        assert!(names(&layout.providers()).is_empty());

        let mut content = String::new();
        io::Read::read_to_string(&mut held, &mut content).unwrap();
        assert_eq!(content, "key-1", "an open descriptor keeps its generation");

        // Nothing but the published generation is ever left in the store.
        assert_eq!(names(&layout.public()), ["providers"]);
        assert!(names(&layout.staging()).is_empty());
    }

    #[test]
    fn readers_never_observe_a_missing_partial_or_mixed_generation() {
        const FILES: [&str; 3] = ["acme/client.toml", "acme/key.pem", "other/token"];
        // Every generation holds the same three files, so an open by path
        // must succeed throughout, as an injected descriptor always did.
        let grace = Duration::from_millis(400);
        let layout = TestStore::new();
        // Room for every replaced generation, so no update waits and the
        // exchange is exercised as fast as it can run.
        let store = layout
            .open_retaining(Retention {
                grace,
                max_generations: 1_024,
                max_bytes: usize::MAX,
            })
            .unwrap();
        let generation = |token: usize| {
            let token = token.to_string();
            files(&[
                (ACME_CONFIG, &token),
                (ACME_KEY, &token),
                (OTHER_TOKEN, &token),
            ])
        };
        store.publish(&generation(0)).unwrap();

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let by_path = {
            let providers = layout.providers();
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut newest = 0_usize;
                let mut observed = 0_usize;
                while !stop.load(std::sync::atomic::Ordering::Acquire) {
                    for name in FILES {
                        let content = std::fs::read_to_string(providers.join(name))
                            .unwrap_or_else(|error| panic!("{name} by path: {error}"));
                        // Complete content of some generation, never older
                        // than one this reader already saw at that path walk.
                        let token: usize = content
                            .parse()
                            .unwrap_or_else(|_| panic!("partial content {content:?}"));
                        newest = newest.max(token);
                        observed += 1;
                    }
                }
                (observed, newest)
            })
        };
        let pinned = {
            let providers = layout.providers();
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut observed = 0_usize;
                while !stop.load(std::sync::atomic::Ordering::Acquire) {
                    // Pin whichever generation is published, then read all
                    // of it: every file exists and carries one token, even
                    // though the generation may be replaced meanwhile.
                    let started = Instant::now();
                    let directory = rustix::fs::open(
                        &providers,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .expect("a generation is always published");
                    let contents = FILES.map(|name| {
                        rustix::fs::openat(
                            &directory,
                            name,
                            OFlags::RDONLY | OFlags::CLOEXEC,
                            Mode::empty(),
                        )
                        .map(|file| {
                            let mut content = String::new();
                            io::Read::read_to_string(&mut File::from(file), &mut content).unwrap();
                            content
                        })
                    });
                    // A reader stalled past the grace may find its pinned
                    // generation removed; that is the documented bound.
                    if started.elapsed() >= grace / 2 {
                        continue;
                    }
                    let [first, second, third] =
                        contents.map(|content| content.expect("pinned generation is complete"));
                    assert!(!first.is_empty(), "file published before its content");
                    assert_eq!(second, first);
                    assert_eq!(third, first);
                    observed += 1;
                }
                observed
            })
        };
        for token in 1..300 {
            store.publish(&generation(token)).unwrap();
        }
        stop.store(true, std::sync::atomic::Ordering::Release);
        let (observed, newest) = by_path.join().expect("path reader");
        assert!(observed > 0 && newest <= 299);
        assert!(pinned.join().expect("pinning reader") > 0);
        assert_eq!(layout.read(ACME_KEY).unwrap(), "299");

        // Replaced generations are removed once their grace has passed, by
        // one thread however many updates there were.
        let deadline = Instant::now() + Duration::from_secs(20);
        while !names(&layout.staging()).is_empty() {
            assert!(Instant::now() < deadline, "replaced generations remain");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(names(&layout.public()), ["providers"]);
        let state = store.shared.lock();
        assert!(state.retired.is_empty());
    }

    #[test]
    fn a_replaced_generation_is_kept_for_its_grace_and_then_removed() {
        let grace = Duration::from_millis(300);
        let layout = TestStore::new();
        let store = layout.open_with_grace(grace).unwrap();
        // Opening removes at once: no workload exists yet.
        assert!(names(&layout.staging()).is_empty());
        store.publish(&files(&[(ACME_KEY, "key-1")])).unwrap();
        let replaced = Instant::now();
        store.publish(&files(&[(ACME_KEY, "key-2")])).unwrap();
        // The replaced generation has no public path...
        assert_eq!(names(&layout.public()), ["providers"]);
        assert_eq!(layout.read(ACME_KEY).unwrap(), "key-2");
        // ...but is still in staging unless the grace already passed.
        let retained = names(&layout.staging());
        if replaced.elapsed() < grace / 2 {
            assert_eq!(retained.len(), 2, "the empty and the first generation");
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        while !names(&layout.staging()).is_empty() {
            assert!(Instant::now() < deadline, "replaced generation remains");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(replaced.elapsed() >= grace, "removed before its grace");
        assert_eq!(layout.read(ACME_KEY).unwrap(), "key-2");
    }

    fn wait_until(mut condition: impl FnMut() -> bool, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !condition() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn a_burst_of_updates_waits_instead_of_retaining_without_bound() {
        let grace = Duration::from_millis(400);
        let layout = TestStore::new();
        let store = layout
            .open_retaining(Retention {
                grace,
                max_generations: 2,
                max_bytes: usize::MAX,
            })
            .unwrap();
        let started = Instant::now();
        for token in 0..7 {
            store
                .publish(&files(&[(ACME_KEY, &token.to_string())]))
                .unwrap();
            // Never more than the bound, however fast updates arrive.
            assert!(
                names(&layout.staging()).len() <= 2,
                "retained generations exceed the bound"
            );
            assert!(store.shared.lock().retired.len() <= 2);
            assert_eq!(layout.read(ACME_KEY).unwrap(), token.to_string());
        }
        // Seven updates retain seven generations, two at a time: at least
        // two full graces must have passed.
        assert!(
            started.elapsed() >= grace * 2,
            "a burst outran the retention bound: {:?}",
            started.elapsed()
        );
        // Everything is reclaimed afterwards, and the reaper stops.
        wait_until(|| names(&layout.staging()).is_empty(), "reclaim");
        wait_until(|| !store.shared.lock().reaping, "the reaper to stop");
        assert!(store.shared.lock().retired.is_empty());
    }

    #[test]
    fn an_identical_update_publishes_and_retains_nothing() {
        let layout = TestStore::new();
        // One retained generation at most, kept far longer than the test: a
        // second exchange would wait out the whole grace.
        let store = layout
            .open_retaining(Retention {
                grace: Duration::from_mins(10),
                max_generations: 1,
                max_bytes: usize::MAX,
            })
            .unwrap();
        let desired = files(&[(ACME_KEY, "key-1"), (OTHER_TOKEN, "token")]);
        store.publish(&desired).unwrap();
        let retained = names(&layout.staging());
        assert_eq!(retained.len(), 1, "the empty first generation");
        let inode = std::fs::metadata(layout.providers()).unwrap().ino();
        let mut held = File::open(layout.providers().join("acme/key.pem")).unwrap();

        let started = Instant::now();
        for _ in 0..64 {
            store.publish(&desired).unwrap();
        }
        assert!(started.elapsed() < Duration::from_mins(1));
        assert_eq!(names(&layout.staging()), retained);
        assert_eq!(store.shared.lock().retired.len(), 1);
        assert_eq!(
            std::fs::metadata(layout.providers()).unwrap().ino(),
            inode,
            "an identical update exchanged the generation"
        );
        assert_eq!(layout.read(ACME_KEY).unwrap(), "key-1");
        let mut content = String::new();
        io::Read::read_to_string(&mut held, &mut content).unwrap();
        assert_eq!(content, "key-1");
    }

    #[test]
    fn an_identical_update_still_ends_a_mode_denial() {
        let layout = TestStore::new();
        let store = layout.open().unwrap();
        let desired = files(&[(ACME_KEY, "key-1"), (OTHER_TOKEN, "token")]);
        store.publish(&desired).unwrap();
        for (path, mode) in [
            (layout.providers().join("acme/key.pem"), 0o000),
            (layout.providers().join("other"), 0o000),
            (layout.providers(), 0o000),
            (layout.providers().join("acme/key.pem"), 0o644),
        ] {
            // Start from an intact generation each time.
            store.publish(&desired).unwrap();
            let inode = std::fs::metadata(layout.providers()).unwrap().ino();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            store.publish(&desired).unwrap();
            assert_ne!(
                std::fs::metadata(layout.providers()).unwrap().ino(),
                inode,
                "{path:?} kept mode {mode:o}"
            );
            assert_eq!(layout.read(ACME_KEY).unwrap(), "key-1");
            assert_eq!(layout.read(OTHER_TOKEN).unwrap(), "token");
            assert_eq!(
                std::fs::metadata(layout.providers().join("acme/key.pem"))
                    .unwrap()
                    .mode()
                    & 0o7777,
                0o600
            );
        }
        // A different map of the same size is a real update.
        store
            .publish(&files(&[(ACME_KEY, "key-2"), (OTHER_TOKEN, "token")]))
            .unwrap();
        assert_eq!(layout.read(ACME_KEY).unwrap(), "key-2");
    }

    #[test]
    fn retained_bytes_are_bounded_and_exhaustion_changes_nothing() {
        let grace = Duration::from_millis(300);
        let layout = TestStore::new();
        let store = layout
            .open_retaining(Retention {
                grace,
                max_generations: 64,
                max_bytes: 10,
            })
            .unwrap();
        store.publish(&files(&[(ACME_KEY, "12345678")])).unwrap();
        store.publish(&files(&[(ACME_KEY, "abcdefgh")])).unwrap();
        // Eight bytes are retained and eight published: a third update must
        // wait for the retained generation to age out.
        let waited = Instant::now();
        store.publish(&files(&[(ACME_KEY, "ABCDEFGH")])).unwrap();
        assert!(waited.elapsed() >= grace / 2, "{:?}", waited.elapsed());
        assert!(store.shared.lock().retired_bytes() <= 10);

        // A published generation larger than the whole bound can never be
        // retained, so replacing it is refused before anything is written.
        let large = "x".repeat(20);
        store.publish(&files(&[(ACME_KEY, &large)])).unwrap();
        let staged = names(&layout.staging());
        let error = store
            .publish(&files(&[(ACME_KEY, "next")]))
            .expect_err("the bound cannot be met");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(layout.read(ACME_KEY).unwrap(), large);
        assert!(
            names(&layout.staging())
                .iter()
                .all(|name| staged.contains(name)),
            "a refused update staged a generation"
        );
    }

    #[test]
    fn a_generation_that_cannot_be_removed_stays_counted() {
        let grace = Duration::from_millis(100);
        let layout = TestStore::new();
        let store = layout
            .open_retaining(Retention {
                grace,
                max_generations: 1,
                max_bytes: usize::MAX,
            })
            .unwrap();
        store.publish(&files(&[(ACME_KEY, "key-1")])).unwrap();
        // Nest the retired generation deeper than the store ever writes, so
        // its removal fails.
        let retired = names(&layout.staging());
        assert_eq!(retired.len(), 1);
        let obstacle = layout.staging().join(&retired[0]).join("a/b/c/d");
        std::fs::create_dir_all(&obstacle).unwrap();
        // The reaper tries once, fails, and stops rather than spin.
        wait_until(
            || {
                let state = store.shared.lock();
                !state.reaping && state.retired.iter().all(|retired| retired.removal_failed)
            },
            "the failed removal",
        );
        assert_eq!(store.shared.lock().retired.len(), 1, "still counted");

        // Its budget is not released, so the next update is refused, at
        // once, with the published generation untouched.
        let refused = Instant::now();
        let error = store
            .publish(&files(&[(ACME_KEY, "key-2")]))
            .expect_err("no room while the removal keeps failing");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(refused.elapsed() < Duration::from_secs(5));
        assert_eq!(layout.read(ACME_KEY).unwrap(), "key-1");
        assert_eq!(names(&layout.staging()), retired);

        // Once it can be removed, the next publication reclaims it.
        std::fs::remove_dir_all(layout.staging().join(&retired[0]).join("a")).unwrap();
        store.publish(&files(&[(ACME_KEY, "key-2")])).unwrap();
        assert_eq!(layout.read(ACME_KEY).unwrap(), "key-2");
        assert!(!names(&layout.staging()).contains(&retired[0]));
        wait_until(|| names(&layout.staging()).is_empty(), "reclaim");
    }

    #[test]
    fn restart_recovers_from_modes_cleared_by_an_earlier_workload() {
        let layout = TestStore::new();
        let store = layout.open().unwrap();
        store.publish(&files(&[(ACME_KEY, "key-1")])).unwrap();
        drop(store);
        // Leftovers of an interrupted update, then every mode cleared.
        std::fs::create_dir_all(layout.staging().join("generation-old/acme")).unwrap();
        std::fs::write(layout.staging().join("generation-old/acme/key.pem"), "old").unwrap();
        for path in [
            layout.staging().join("generation-old/acme/key.pem"),
            layout.staging().join("generation-old/acme"),
            layout.staging().join("generation-old"),
            layout.providers().join("acme/key.pem"),
            layout.providers().join("acme"),
            layout.providers(),
            layout.staging(),
            layout.public(),
        ] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)).unwrap();
        }

        let store = layout.open().expect("restart");
        // The earlier run's provider files are gone, not merely hidden.
        assert!(names(&layout.providers()).is_empty());
        assert!(names(&layout.staging()).is_empty());
        assert_eq!(
            std::fs::metadata(layout.public()).unwrap().mode() & 0o7777,
            0o755
        );
        store.publish(&files(&[(ACME_KEY, "key-2")])).unwrap();
        assert_eq!(layout.read(ACME_KEY).unwrap(), "key-2");
    }

    const LANDLOCKED_CHILD: &str = "OPENSHELL_PROVIDER_STORE_LANDLOCKED_CHILD";

    /// `truncate(2)` by path, which needs no descriptor.
    #[allow(unsafe_code)]
    fn truncate_path(path: &Path) -> io::Result<()> {
        let path = CString::new(path.to_str().unwrap()).unwrap();
        // SAFETY: the path is a live NUL-terminated string.
        if unsafe { libc::truncate(path.as_ptr(), 0) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Runs only as the re-executed child of
    /// `chmod_through_the_private_path_cannot_reach_content`.
    ///
    /// It confines itself the way the mandatory baseline confines a
    /// workload: no Landlock right anywhere beneath the private root. A
    /// read-only rule on `public` stands in for the read-only mount, which a
    /// test cannot make; unlike the mount, Landlock does not refuse `chmod`
    /// there either, which only makes this child stronger than a workload.
    #[test]
    fn landlocked_workload_child() {
        use landlock::{
            ABI, Access as _, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr as _,
            RulesetCreatedAttr as _, RulesetStatus,
        };
        let Some(arguments) = std::env::var_os(LANDLOCKED_CHILD) else {
            return;
        };
        let arguments = arguments.into_string().unwrap();
        let (root, retired) = arguments.split_once('\n').unwrap();
        let root = Path::new(root);
        let status = Ruleset::default()
            .handle_access(AccessFs::from_all(ABI::V3))
            .unwrap()
            .create()
            .unwrap()
            .add_rule(PathBeneath::new(
                PathFd::new(root.join("public")).unwrap(),
                AccessFs::from_read(ABI::V3),
            ))
            .unwrap()
            .restrict_self()
            .unwrap();
        assert_eq!(status.ruleset, RulesetStatus::FullyEnforced);

        let denied = |result: io::Result<()>, what: &str| {
            let error = result.expect_err(what);
            assert!(
                matches!(error.raw_os_error(), Some(libc::EACCES | libc::EXDEV)),
                "{what}: {error}"
            );
        };
        let writable = std::fs::Permissions::from_mode(0o666);
        let open = std::fs::Permissions::from_mode(0o777);
        let staged_directory = root.join("staging").join(retired).join("acme");
        let staged = staged_directory.join("key.pem");
        let published = root.join("public/providers/acme/key.pem");

        // The private path gives no access to content or names.
        denied(std::fs::read(&staged).map(drop), "read a staged file");
        denied(
            std::fs::read_dir(root.join("staging")).map(drop),
            "list staging",
        );
        // Landlock does not mediate chmod: the workload owns these files and
        // may change every mode on the way.
        for path in [
            root.join("staging"),
            root.join("staging").join(retired),
            staged_directory.clone(),
        ] {
            std::fs::set_permissions(path, open.clone()).expect("chmod is not mediated");
        }
        std::fs::set_permissions(&staged, writable.clone()).expect("chmod is not mediated");
        // The widest modes still open nothing.
        denied(std::fs::read(&staged).map(drop), "read after chmod");
        denied(
            std::fs::OpenOptions::new()
                .write(true)
                .open(&staged)
                .map(drop),
            "write after chmod",
        );
        denied(
            std::fs::OpenOptions::new()
                .append(true)
                .open(&staged)
                .map(drop),
            "append after chmod",
        );
        denied(truncate_path(&staged), "truncate after chmod");
        denied(std::fs::remove_file(&staged), "unlink after chmod");
        denied(
            std::fs::rename(&staged, staged_directory.join("moved")),
            "rename after chmod",
        );
        denied(
            std::fs::rename(&staged, root.join("public/providers/acme/planted")),
            "move into the published generation",
        );
        denied(
            std::fs::hard_link(&staged, root.join("public/providers/acme/linked")),
            "link into the published generation",
        );
        denied(
            std::fs::write(staged_directory.join("planted"), "x"),
            "create in staging",
        );
        denied(
            std::fs::create_dir(root.join("staging/planted")),
            "create a generation",
        );
        denied(
            std::fs::rename(
                root.join("staging").join(retired),
                root.join("public/providers"),
            ),
            "replace the published generation",
        );

        // Published content is readable and stays unchangeable.
        assert_eq!(std::fs::read_to_string(&published).unwrap(), "key-2");
        std::fs::set_permissions(&published, writable).expect("chmod is not mediated");
        denied(
            std::fs::OpenOptions::new()
                .write(true)
                .open(&published)
                .map(drop),
            "write a published file",
        );
        denied(truncate_path(&published), "truncate a published file");
        denied(std::fs::remove_file(&published), "unlink a published file");
        denied(
            std::fs::write(root.join("public/providers/acme/planted"), "x"),
            "create a published file",
        );
        assert_eq!(std::fs::read_to_string(&published).unwrap(), "key-2");

        // All a mode change achieves: deny the workload its own files.
        let cleared = std::fs::Permissions::from_mode(0o000);
        std::fs::set_permissions(&published, cleared.clone()).unwrap();
        std::fs::set_permissions(root.join("public/providers"), cleared.clone()).unwrap();
        std::fs::set_permissions(root.join("staging"), cleared).unwrap();
        assert!(std::fs::read(&published).is_err());
    }

    #[test]
    fn chmod_through_the_private_path_cannot_reach_content() {
        let layout = TestStore::new();
        // Keep the replaced generation in staging for the child to attack.
        let store = layout.open_with_grace(Duration::from_mins(10)).unwrap();
        store.publish(&files(&[(ACME_KEY, "key-1")])).unwrap();
        store.publish(&files(&[(ACME_KEY, "key-2")])).unwrap();
        let retired = names(&layout.staging())
            .into_iter()
            .find(|name| layout.staging().join(name).join("acme/key.pem").exists())
            .expect("the replaced generation");
        let staged = layout.staging().join(&retired).join("acme/key.pem");

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "provider_store::tests::landlocked_workload_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(
                LANDLOCKED_CHILD,
                format!("{}\n{retired}", layout.root.display()),
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "confined workload reached store content:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "the confined child did not run"
        );

        // Nothing the child did changed content or names...
        for (path, content) in [
            (staged, "key-1"),
            (layout.providers().join("acme/key.pem"), "key-2"),
        ] {
            for ancestor in [layout.staging(), layout.providers()] {
                std::fs::set_permissions(ancestor, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(std::fs::read_to_string(&path).unwrap(), content);
        }
        assert_eq!(names(&layout.providers().join("acme")), ["key.pem"]);
        assert_eq!(
            names(&layout.staging().join(&retired).join("acme")),
            ["key.pem"]
        );
        assert_eq!(names(&layout.public()), ["providers"]);
        // ...and the modes it cleared do not survive the next update.
        for path in [layout.providers(), layout.staging()] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        store.publish(&files(&[(ACME_KEY, "key-3")])).unwrap();
        assert_eq!(layout.read(ACME_KEY).unwrap(), "key-3");
        assert_eq!(
            std::fs::metadata(layout.providers().join("acme/key.pem"))
                .unwrap()
                .mode()
                & 0o7777,
            0o600
        );
    }

    #[test]
    fn a_failed_publication_leaves_the_previous_generation() {
        let layout = TestStore::new();
        let store = layout.open().unwrap();
        store.publish(&files(&[(ACME_KEY, "key-1")])).unwrap();
        // The caller validates paths first; an invalid one that reached the
        // store must still not disturb what is published.
        let error = store
            .publish(&files(&[
                (ACME_KEY, "key-2"),
                ("/run/openshell/providers/acme/../escape", "x"),
            ]))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(layout.read(ACME_KEY).unwrap(), "key-1");
        assert!(names(&layout.staging()).is_empty());
        assert!(!layout.root.join("escape").exists());
        assert!(!layout.public().join("escape").exists());
    }

    #[test]
    fn symlinked_store_directories_are_refused() {
        for replaced in ["public", "staging"] {
            let layout = TestStore::new();
            let elsewhere = tempfile::tempdir().unwrap();
            std::fs::remove_dir(layout.root.join(replaced)).unwrap();
            std::os::unix::fs::symlink(elsewhere.path(), layout.root.join(replaced)).unwrap();
            assert!(layout.open().is_err(), "{replaced} symlink must be refused");
            assert!(names(elsewhere.path()).is_empty());
        }
    }

    #[test]
    fn a_public_root_that_is_not_the_stores_directory_is_refused() {
        let layout = TestStore::new();
        let unrelated = tempfile::tempdir().unwrap();
        let error = NativeStore::open_roots(
            layout.root_fd(),
            unrelated.path(),
            PublicMount::AnyForTest,
            IMMEDIATE,
        )
        .err()
        .expect("an unrelated public root");
        assert!(
            error
                .to_string()
                .contains("not the store's public directory")
        );
        // A symlink at the public root is not followed either.
        let link = unrelated.path().join("link");
        std::os::unix::fs::symlink(layout.public(), &link).unwrap();
        assert!(
            NativeStore::open_roots(layout.root_fd(), &link, PublicMount::AnyForTest, IMMEDIATE)
                .is_err()
        );
    }

    #[test]
    fn a_writable_public_mount_is_refused() {
        // A temporary directory is not a read-only mount, so the production
        // requirement must reject it and publish nothing.
        let layout = TestStore::new();
        let error = NativeStore::open_roots(
            layout.root_fd(),
            &layout.public(),
            PublicMount::RequireReadOnly,
            IMMEDIATE,
        )
        .err()
        .expect("a writable public root");
        assert!(error.to_string().contains("not a read-only mount"));
        assert!(names(&layout.public()).is_empty());
    }

    #[test]
    fn unexpected_public_entries_are_refused() {
        let layout = TestStore::new();
        std::fs::write(layout.public().join("planted"), "x").unwrap();
        assert!(layout.open().is_err());
    }

    #[test]
    fn configured_roots_must_be_the_reserved_paths() {
        let store = |private_root: &str, public_root: &str| ProviderFileStore {
            private_root: private_root.into(),
            public_root: public_root.into(),
        };
        for (private_root, public_root) in [
            // The public root is fixed by the provider path contract.
            ("/.openshell/provider-files", "/run/other"),
            ("/.openshell/provider-files", "/run/openshell/providers"),
            // The private root must be hidden by the Landlock baseline.
            ("/tmp/provider-files", "/run/openshell"),
            ("/.openshell", "/run/openshell"),
            ("/.openshell/../tmp/store", "/run/openshell"),
            ("/.openshell/./store", "/run/openshell"),
            (".openshell/store", "/run/openshell"),
            ("/.openshellx/store", "/run/openshell"),
        ] {
            let error = NativeStore::open(&store(private_root, public_root))
                .err()
                .unwrap_or_else(|| panic!("{private_root} {public_root} must be refused"));
            // Refused by the path rules, or because this host has no such
            // store; never accepted.
            assert!(
                matches!(
                    error.kind(),
                    io::ErrorKind::InvalidInput
                        | io::ErrorKind::NotFound
                        | io::ErrorKind::PermissionDenied
                        | io::ErrorKind::NotADirectory
                ),
                "{private_root} {public_root}: {error}"
            );
        }
    }

    #[test]
    fn planted_symlinks_are_removed_without_touching_their_targets() {
        let layout = TestStore::new();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("keep"), "keep").unwrap();
        // A symlink where a stale generation would be, one inside a stale
        // generation, and one in place of the published directory.
        std::os::unix::fs::symlink(outside.path(), layout.staging().join("generation-1-x"))
            .unwrap();
        std::fs::create_dir_all(layout.staging().join("generation-2-y")).unwrap();
        std::os::unix::fs::symlink(outside.path(), layout.staging().join("generation-2-y/acme"))
            .unwrap();
        std::os::unix::fs::symlink(outside.path(), layout.providers()).unwrap();

        let store = layout.open().unwrap();
        store.publish(&files(&[(ACME_KEY, "key")])).unwrap();
        assert_eq!(layout.read(ACME_KEY).unwrap(), "key");
        assert!(
            std::fs::symlink_metadata(layout.providers())
                .unwrap()
                .is_dir(),
            "the published entry is a real directory"
        );
        assert!(names(&layout.staging()).is_empty());
        assert_eq!(names(outside.path()), ["keep"]);
        assert_eq!(
            std::fs::read_to_string(outside.path().join("keep")).unwrap(),
            "keep"
        );
    }

    #[test]
    fn cleared_modes_do_not_block_the_next_publication() {
        // The workload shares the store's UID. Landlock keeps it from
        // reading or writing through the private path but does not mediate
        // chmod, so the runtime must survive modes the workload cleared.
        let layout = TestStore::new();
        let store = layout.open().unwrap();
        store.publish(&files(&[(ACME_KEY, "key-1")])).unwrap();
        let clear = |path: PathBuf| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)).unwrap();
        };
        clear(layout.providers().join("acme/key.pem"));
        clear(layout.providers().join("acme"));
        clear(layout.providers());
        clear(layout.staging());
        clear(layout.public());

        store.publish(&files(&[(ACME_KEY, "key-2")])).unwrap();
        assert_eq!(layout.read(ACME_KEY).unwrap(), "key-2");
        assert_eq!(
            std::fs::metadata(layout.public()).unwrap().mode() & 0o7777,
            0o755
        );
        assert!(names(&layout.staging()).is_empty());
    }

    /// Read access to `public` and nothing else, as the calling thread's
    /// Landlock domain. `public` is a plain directory here, not a mount, so
    /// a generation exchanged out of it is refused on every kernel: the
    /// answer an unqualified kernel gives under the driver's mounts.
    fn confine_to(public: PathBuf) -> impl FnOnce() -> io::Result<()> + Send {
        use landlock::{
            ABI, Access as _, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr as _,
            RulesetCreatedAttr as _, RulesetStatus,
        };
        move || {
            let status = Ruleset::default()
                .handle_access(AccessFs::from_all(ABI::V3))
                .and_then(Ruleset::create)
                .and_then(|ruleset| {
                    ruleset.add_rule(PathBeneath::new(
                        PathFd::new(public).expect("public directory"),
                        AccessFs::from_read(ABI::V3),
                    ))
                })
                .and_then(landlock::RulesetCreated::restrict_self)
                .map_err(io::Error::other)?;
            assert_eq!(status.ruleset, RulesetStatus::FullyEnforced);
            Ok(())
        }
    }

    fn assert_empty(layout: &TestStore) {
        assert_eq!(names(&layout.public()), ["providers"]);
        assert!(names(&layout.providers()).is_empty());
        assert!(names(&layout.staging()).is_empty());
    }

    #[test]
    fn a_refused_probe_open_selects_no_store_and_leaves_it_empty() {
        let layout = TestStore::new();
        // An earlier run's provider file, at the path a relative open reads.
        std::fs::create_dir_all(layout.providers().join("stale")).unwrap();
        std::fs::write(layout.providers().join("stale/secret"), "old").unwrap();

        // Real Landlock on the probe thread, real exchange, real refusal.
        let capability = std::cell::Cell::new(None);
        let store = layout
            .open_with_grace(Duration::from_secs(1))
            .unwrap()
            .qualify(|store| {
                let probed =
                    store.probe(&layout.root, &layout.public(), confine_to(layout.public()));
                capability.set(probed.as_ref().ok().copied());
                probed
            })
            .expect("a refused open is an answer, not a failure");
        assert_eq!(capability.get(), Some(Capability::Unqualified));
        assert!(store.is_none(), "an unqualified kernel got a native store");
        assert_empty(&layout);
        // The probe confined its own thread, which is gone; this one still
        // reads the private side.
        assert!(std::fs::read_dir(layout.staging()).is_ok());
    }

    #[test]
    fn an_incomplete_probe_fails_and_restores_the_store() {
        let layout = TestStore::new();
        let store = layout.open().unwrap();
        // A confinement that hides nothing proves nothing.
        let error = store
            .probe(&layout.root, &layout.public(), || Ok(()))
            .expect_err("the private root stayed readable");
        assert!(error.to_string().contains("does not hide the private root"));
        assert_empty(&layout);
        // A confinement that cannot be applied.
        let error = store
            .probe(&layout.root, &layout.public(), || {
                Err(io::Error::other("no landlock"))
            })
            .expect_err("unconfined probe");
        assert!(error.to_string().contains("no landlock"));
        assert_empty(&layout);
        // A public root that does not show the probe file.
        let elsewhere = tempfile::tempdir().unwrap();
        std::fs::create_dir(elsewhere.path().join("providers")).unwrap();
        let error = store
            .probe(
                &layout.root,
                elsewhere.path(),
                confine_to(elsewhere.path().to_path_buf()),
            )
            .expect_err("the probe file is not behind this root");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_empty(&layout);
        // A failed probe is never an answer: no store, and no fallback.
        assert!(
            store
                .qualify(|_| Err(io::Error::other("incomplete")))
                .is_err()
        );
    }

    #[test]
    fn qualification_keeps_or_drops_the_store_only_while_it_is_empty() {
        let layout = TestStore::new();
        let store = layout
            .open()
            .unwrap()
            .qualify(|_| Ok(Capability::Qualified))
            .unwrap()
            .expect("a qualified kernel keeps the store");
        store.publish(&files(&[(ACME_KEY, "key-1")])).unwrap();
        assert_eq!(layout.read(ACME_KEY).unwrap(), "key-1");
        drop(store);

        // Reopening clears that run, so the fallback is allowed.
        assert!(
            layout
                .open()
                .unwrap()
                .qualify(|_| Ok(Capability::Unqualified))
                .unwrap()
                .is_none()
        );
        assert_empty(&layout);

        // Anything left at the provider path, or in staging, refuses both
        // answers: virtual delivery must not leave a file a relative open
        // can read, and native delivery must not start from a dirty store.
        for capability in [Capability::Unqualified, Capability::Qualified] {
            for left_in in ["public/providers/acme", "staging/generation-left"] {
                let layout = TestStore::new();
                let result = layout.open().unwrap().qualify(|_| {
                    std::fs::create_dir(layout.root.join(left_in)).unwrap();
                    Ok(capability)
                });
                let error = result.err().expect("a store that is not empty");
                assert!(error.to_string().contains("not empty"), "{error}");
            }
        }
    }

    /// Exercises production validation against the mounts a driver makes.
    ///
    /// Run it inside a container that mounts one volume at
    /// `/.openshell/provider-files` (writable) and that volume's `public`
    /// subdirectory at `/run/openshell` (read-only), as the unprivileged
    /// identity owning `public` and `staging`. It cannot run on a host,
    /// which has no such mounts.
    #[test]
    #[ignore = "requires the driver's provider-file mounts"]
    fn production_validation_accepts_a_driver_mounted_store() {
        let config = ProviderFileStore {
            private_root: "/.openshell/provider-files".into(),
            public_root: PUBLIC_ROOT.into(),
        };
        // Opening runs the real capability probe: a thread under the real
        // baseline and public grant, on the real mounts.
        let store = NativeStore::open(&config)
            .expect("driver-mounted store")
            .expect("this kernel keeps an exchanged-out generation readable");
        assert!(names(&Path::new(PUBLIC_ROOT).join("providers")).is_empty());
        assert_eq!(names(Path::new(PUBLIC_ROOT)), ["providers"]);
        // The probe confined its own thread only, and left nothing behind.
        assert!(names(&Path::new(PRIVATE_ROOT).join("staging")).is_empty());
        store
            .publish(&files(&[(ACME_KEY, "key-1"), (OTHER_TOKEN, "token")]))
            .unwrap();
        // The workload's view: the real provider path, on the read-only mount.
        assert_eq!(std::fs::read_to_string(ACME_KEY).unwrap(), "key-1");
        let mut held = File::open(ACME_KEY).unwrap();
        let read_only = |error: io::Error| {
            assert_eq!(error.raw_os_error(), Some(libc::EROFS), "{error}");
        };
        assert_eq!(
            std::fs::metadata(ACME_KEY).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        // Same UID and an owner-writable mode, yet the public mount refuses
        // content and metadata changes.
        read_only(
            std::fs::OpenOptions::new()
                .write(true)
                .open(ACME_KEY)
                .unwrap_err(),
        );
        read_only(
            std::fs::OpenOptions::new()
                .append(true)
                .open(ACME_KEY)
                .unwrap_err(),
        );
        read_only(
            std::fs::set_permissions(ACME_KEY, std::fs::Permissions::from_mode(0o666)).unwrap_err(),
        );
        read_only(
            std::fs::set_permissions(
                "/run/openshell/providers",
                std::fs::Permissions::from_mode(0o777),
            )
            .unwrap_err(),
        );
        read_only(std::fs::remove_file(ACME_KEY).unwrap_err());
        read_only(std::fs::write("/run/openshell/providers/acme/planted", "x").unwrap_err());
        read_only(std::fs::write("/run/openshell/planted", "x").unwrap_err());
        read_only(std::fs::rename(ACME_KEY, "/run/openshell/providers/acme/moved").unwrap_err());
        read_only(
            held.set_permissions(std::fs::Permissions::from_mode(0o666))
                .unwrap_err(),
        );
        // Staging and replaced generations have no public path.
        assert_eq!(names(Path::new(PUBLIC_ROOT)), ["providers"]);

        store.publish(&files(&[(ACME_KEY, "key-2")])).unwrap();
        assert_eq!(std::fs::read_to_string(ACME_KEY).unwrap(), "key-2");
        assert_eq!(
            std::fs::read(OTHER_TOKEN).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        let mut content = String::new();
        io::Read::read_to_string(&mut held, &mut content).unwrap();
        assert_eq!(content, "key-1");
        assert_eq!(names(Path::new(PUBLIC_ROOT)), ["providers"]);

        // A restart reopens the store and clears the previous run.
        drop(store);
        let store = NativeStore::open(&config)
            .expect("reopen")
            .expect("qualified");
        assert!(names(&Path::new(PUBLIC_ROOT).join("providers")).is_empty());
        assert_eq!(
            std::fs::read(ACME_KEY).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );

        // A kernel that refused the probed open, injected here because this
        // kernel does not, gets no store, and nothing an earlier run
        // published stays readable at the provider path.
        store.publish(&files(&[(ACME_KEY, "key-3")])).unwrap();
        drop(store);
        let reopened = NativeStore::open_roots(
            open_private_root(Path::new(PRIVATE_ROOT)).unwrap(),
            Path::new(PUBLIC_ROOT),
            PublicMount::RequireReadOnly,
            Retention::PRODUCTION,
        )
        .unwrap()
        .qualify(|_| Ok(Capability::Unqualified))
        .expect("an empty store may fall back");
        assert!(reopened.is_none());
        assert_eq!(names(Path::new(PUBLIC_ROOT)), ["providers"]);
        assert!(names(&Path::new(PUBLIC_ROOT).join("providers")).is_empty());
        assert!(names(&Path::new(PRIVATE_ROOT).join("staging")).is_empty());
    }

    const CONFINED_READER: &str = "OPENSHELL_PROVIDER_STORE_CONFINED_READER";
    const PRIVATE_ROOT: &str = "/.openshell/provider-files";

    fn errno_name(error: &io::Error) -> String {
        match error.raw_os_error() {
            Some(libc::EACCES) => "EACCES".into(),
            Some(libc::ENOENT) => "ENOENT".into(),
            Some(other) => format!("errno{other}"),
            None => format!("{:?}", error.kind()),
        }
    }

    /// Runs only as the re-executed child of
    /// `confined_absolute_opens_survive_publication`, inside the driver's
    /// mounts.
    ///
    /// It confines itself with the Landlock layers a workload gets: the
    /// mandatory baseline, and for `policy` a user filesystem policy carrying
    /// the automatic read grant of the public root. Then it reads provider
    /// files by absolute path while the parent publishes, and reports every
    /// outcome on stdout for the parent to judge.
    #[test]
    fn confined_reader_child() {
        use std::io::BufRead as _;

        let Some(mode) = std::env::var_os(CONFINED_READER) else {
            return;
        };
        let mode = mode.into_string().unwrap();
        let (layers, seconds) = mode.split_once(':').unwrap();
        let duration = Duration::from_millis(seconds.parse().unwrap());
        let mut policy = openshell_core::policy::SandboxPolicy {
            version: 1,
            filesystem: openshell_core::policy::FilesystemPolicy::default(),
            network: openshell_core::policy::NetworkPolicy::default(),
            landlock: openshell_core::policy::LandlockPolicy {
                compatibility: openshell_core::policy::LandlockCompatibility::HardRequirement,
            },
            process: openshell_core::policy::ProcessPolicy::default(),
        };
        if layers == "policy" {
            policy.filesystem.read_only = vec!["/usr".into()];
            crate::process::grant_native_provider_files(
                &mut policy,
                None,
                Some(Path::new(PUBLIC_ROOT)),
            );
            assert_eq!(policy.filesystem.read_only.len(), 2);
        }
        let prepared = crate::sandbox::linux::prepare_capability_free(&policy, None).unwrap();
        crate::sandbox::linux::enforce_landlock(prepared).unwrap();

        // The private alias of the same files stays closed.
        for path in [
            format!("{PRIVATE_ROOT}/staging"),
            format!("{PRIVATE_ROOT}/public/providers/acme/key.pem"),
        ] {
            let error = File::open(&path).expect_err("private path opened");
            assert_eq!(error.raw_os_error(), Some(libc::EACCES), "{path}: {error}");
        }

        let mut held = File::open(ACME_KEY).unwrap();
        let first = std::fs::read_to_string(ACME_KEY).unwrap();
        let open_directory = || {
            rustix::fs::open(
                "/run/openshell/providers",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap()
        };
        let open_beneath = |directory: &OwnedFd| -> String {
            match rustix::fs::openat(
                directory,
                "acme/key.pem",
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(_) => "ok".into(),
                Err(error) => errno_name(&error.into()),
            }
        };

        // One exchange between resolving the published directory and opening
        // a file beneath it: the state of an open caught mid-walk.
        let pinned = open_directory();
        println!("READER pinned");
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "exchanged");
        println!("READER walk-after-exchange {}", open_beneath(&pinned));

        let mut outcomes: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        let mut count = |kind: &str, outcome: String| {
            *outcomes.entry(format!("{kind}:{outcome}")).or_default() += 1;
        };
        let started = Instant::now();
        while started.elapsed() < duration {
            for path in [ACME_CONFIG, ACME_KEY, OTHER_TOKEN] {
                let outcome = match std::fs::read_to_string(path) {
                    Ok(content) if content.parse::<usize>().is_ok() => "ok".into(),
                    Ok(content) => format!("partial({content:?})"),
                    Err(error) => errno_name(&error),
                };
                count("absolute", outcome);
            }
            // The same race, widened: resolve the directory, then open.
            count("two-step", open_beneath(&open_directory()));
        }
        for (outcome, total) in &outcomes {
            println!("READER {outcome} {total}");
        }
        let mut content = String::new();
        io::Read::read_to_string(&mut held, &mut content).unwrap();
        println!(
            "READER held-descriptor {}",
            if content == first { "ok" } else { "changed" }
        );
        println!("READER done");
    }

    /// Establishes what Landlock does to a workload's ordinary absolute
    /// provider-file opens while generations are exchanged.
    ///
    /// The exchange moves the replaced generation out of the public
    /// directory, the only part of the store a workload may read. A kernel
    /// that judged a file by the directories above it at that moment would
    /// refuse an open caught between resolving `providers` and opening the
    /// file, although the file exists in both generations. A kernel that
    /// applies the rights of the mount an open came through does not.
    ///
    /// The confined child reports three things. `walk-after-exchange` is
    /// that mid-walk state made deterministic: a directory resolved before
    /// one exchange, a file opened beneath it right after. `absolute` counts
    /// ordinary opens by absolute path racing continuous exchanges, and
    /// `two-step` widens the same race. Every one must succeed, with and
    /// without a user filesystem policy. A failure here means this kernel
    /// needs another design, not a longer grace.
    ///
    /// Run this inside the mounts described at
    /// `production_validation_accepts_a_driver_mounted_store`, with
    /// `--nocapture` to see the measured outcomes.
    #[test]
    #[ignore = "requires the driver's provider-file mounts"]
    fn confined_absolute_opens_survive_publication() {
        use std::io::{BufRead as _, Write as _};

        const DURATION: Duration = Duration::from_secs(4);
        let generation = |token: usize| {
            let token = token.to_string();
            files(&[
                (ACME_CONFIG, &token),
                (ACME_KEY, &token),
                (OTHER_TOKEN, &token),
            ])
        };
        for layers in ["baseline", "policy"] {
            // Room for every replaced generation, so the exchange runs as
            // fast as it can.
            let store = NativeStore::open_roots(
                open_private_root(Path::new(PRIVATE_ROOT)).unwrap(),
                Path::new(PUBLIC_ROOT),
                PublicMount::RequireReadOnly,
                Retention {
                    grace: Duration::from_secs(1),
                    max_generations: 1_000_000,
                    max_bytes: usize::MAX,
                },
            )
            .expect("driver-mounted store");
            store.publish(&generation(0)).unwrap();

            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "provider_store::tests::confined_reader_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(
                    CONFINED_READER,
                    format!("{layers}:{}", DURATION.as_millis()),
                )
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let mut stdin = child.stdin.take().unwrap();
            let stdout = io::BufReader::new(child.stdout.take().unwrap());
            let (sender, receiver) = std::sync::mpsc::channel();
            let reader = std::thread::spawn(move || {
                let mut report = Vec::new();
                for line in stdout.lines() {
                    let line = line.unwrap();
                    // The harness prints its own prefix on the first line.
                    if line.ends_with("READER pinned") {
                        sender.send(()).unwrap();
                    }
                    report.push(line);
                }
                report
            });
            receiver
                .recv_timeout(Duration::from_secs(30))
                .expect("the confined reader started");
            let mut token = 1;
            store.publish(&generation(token)).unwrap();
            writeln!(stdin, "exchanged").unwrap();
            let mut published = 1_usize;
            while child.try_wait().unwrap().is_none() {
                token += 1;
                store.publish(&generation(token)).unwrap();
                published += 1;
            }
            assert!(child.wait().unwrap().success(), "confined reader failed");
            let report = reader.join().unwrap();
            let outcomes: Vec<&str> = report
                .iter()
                .filter_map(|line| line.split_once("READER ").map(|(_, outcome)| outcome))
                .collect();
            println!("{layers}: {published} publications; {outcomes:?}");
            assert!(outcomes.contains(&"done"), "{report:?}");
            assert!(outcomes.contains(&"held-descriptor ok"), "{outcomes:?}");
            assert!(
                outcomes.contains(&"walk-after-exchange ok"),
                "{layers}: Landlock refused an open caught mid-walk by an exchange: {outcomes:?}"
            );
            assert!(
                published > 100,
                "{layers}: only {published} exchanges raced"
            );
            for kind in ["absolute", "two-step"] {
                let counted: Vec<&&str> = outcomes
                    .iter()
                    .filter(|outcome| outcome.starts_with(kind))
                    .collect();
                assert!(
                    counted.len() == 1 && counted[0].starts_with(&format!("{kind}:ok ")),
                    "{layers}: a confined {kind} open failed during publication: {outcomes:?}"
                );
            }
        }
    }
}
