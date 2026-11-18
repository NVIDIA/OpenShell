// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Workload processes inside the guest: a private mount namespace rooted at
//! the workload rootfs, identity setup, PTY or pipes, a bounded retained
//! output window, signals, and fail-closed teardown.
use crate::launch::{
    PRIVILEGED_BASE_ID, PRIVILEGED_ID_RANGE, Privilege, SHIM_TLS_DIR, WORKLOAD_ROOT,
    WORKLOAD_TLS_DIR,
};
use anyhow::{Context, Result, bail};
use openshell_sandbox::linux::{
    child_seccomp::ChildHardeningProgram, workload_launcher::WorkloadLauncher,
};
use openshell_sandbox_backend::boundary_protocol::ExitStatusWire;
use std::{
    collections::VecDeque,
    ffi::CString,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    os::unix::ffi::OsStringExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::watch,
};

const RETAINED_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const READ_CHUNK: usize = 32 * 1024;
const OUTPUT_DRAIN_GRACE: Duration = Duration::from_secs(2);
const TERMINATE_GRACE: Duration = Duration::from_secs(5);

pub struct SpawnSpec {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub workdir: String,
    /// Columns and rows for a PTY, or `None` for separate pipes.
    pub pty: Option<(u16, u16)>,
}

pub struct Chunk {
    pub channel: u8,
    pub bytes: Vec<u8>,
}

#[derive(Default)]
struct OutputState {
    chunks: VecDeque<(u64, u8, Vec<u8>)>,
    next: u64,
    bytes: usize,
    closed: bool,
}

/// Output retained for attachments. Old chunks drop once the window is full.
#[derive(Default)]
pub struct Output {
    state: Mutex<OutputState>,
    changed: watch::Sender<u64>,
}

impl Output {
    fn push(&self, channel: u8, bytes: &[u8]) {
        let mut state = self.state.lock().unwrap();
        let sequence = state.next;
        state.next += 1;
        state.bytes += bytes.len();
        state.chunks.push_back((sequence, channel, bytes.to_vec()));
        while state.bytes > RETAINED_OUTPUT_BYTES {
            let Some((_, _, old)) = state.chunks.pop_front() else {
                break;
            };
            state.bytes -= old.len();
        }
        let next = state.next;
        drop(state);
        self.changed.send_replace(next);
    }

    fn close(&self) {
        self.state.lock().unwrap().closed = true;
        self.changed.send_modify(|_| {});
    }

    /// Chunks at or after `from`, the next sequence, and whether output ended.
    pub fn read_from(&self, from: u64) -> (Vec<Chunk>, u64, bool) {
        let state = self.state.lock().unwrap();
        let chunks = state
            .chunks
            .iter()
            .filter(|(sequence, _, _)| *sequence >= from)
            .map(|(_, channel, bytes)| Chunk {
                channel: *channel,
                bytes: bytes.clone(),
            })
            .collect();
        (chunks, state.next, state.closed)
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }
}

type Writer = Box<dyn AsyncWrite + Send + Unpin>;

pub struct Process {
    pub id: String,
    pub pty: bool,
    pub pid: i32,
    reaped: Mutex<bool>,
    pub output: Arc<Output>,
    stdin: tokio::sync::Mutex<Option<Writer>>,
    status: watch::Sender<Option<ExitStatusWire>>,
    master: Option<OwnedFd>,
}

impl Process {
    pub async fn write_stdin(&self, bytes: &[u8]) {
        let mut stdin = self.stdin.lock().await;
        if let Some(writer) = stdin.as_mut()
            && writer.write_all(bytes).await.is_err()
        {
            *stdin = None;
        }
    }

    pub async fn close_stdin(&self) {
        // A PTY has no separate input EOF; closing the master would hang up
        // the whole terminal.
        if !self.pty {
            self.stdin.lock().await.take();
        }
    }

    pub fn status(&self) -> Option<ExitStatusWire> {
        *self.status.borrow()
    }

    pub async fn wait(&self) -> ExitStatusWire {
        let mut receiver = self.status.subscribe();
        loop {
            if let Some(status) = *receiver.borrow_and_update() {
                return status;
            }
            if receiver.changed().await.is_err() {
                return ExitStatusWire::Signaled(libc::SIGKILL);
            }
        }
    }

    /// Signal the whole process group created for this process.
    /// Signal the whole process group created for this process. A no-op once
    /// the leader is reaped, so a reused PID is never signalled. Descendants
    /// that left the group are covered by [`kill_workload`] and by the host
    /// stopping the whole guest.
    pub fn signal(&self, signal: i32) {
        let reaped = self.reaped.lock().unwrap();
        if !*reaped {
            // SAFETY: the unreaped leader keeps this PID and group number ours.
            unsafe {
                libc::kill(-self.pid, signal);
            }
        }
    }

    pub fn terminate(self: &Arc<Self>) {
        self.signal(libc::SIGTERM);
        let process = self.clone();
        tokio::spawn(async move {
            if tokio::time::timeout(TERMINATE_GRACE, process.wait())
                .await
                .is_err()
            {
                process.signal(libc::SIGKILL);
            }
        });
    }

    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        let Some(master) = &self.master else {
            bail!("process has no terminal");
        };
        set_window_size(master.as_raw_fd(), cols, rows)
    }
}

fn set_window_size(fd: RawFd, cols: u16, rows: u16) -> Result<()> {
    let size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCSWINSZ reads one initialized winsize from a valid PTY fd.
    if unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &size) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn open_pty(cols: u16, rows: u16) -> Result<(OwnedFd, OwnedFd)> {
    // SAFETY: standard Unix98 PTY allocation; every returned fd is owned below.
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        if master < 0 {
            return Err(std::io::Error::last_os_error()).context("posix_openpt");
        }
        let master = OwnedFd::from_raw_fd(master);
        if libc::grantpt(master.as_raw_fd()) != 0 || libc::unlockpt(master.as_raw_fd()) != 0 {
            return Err(std::io::Error::last_os_error()).context("unlock PTY");
        }
        let mut name = [0 as libc::c_char; 128];
        if libc::ptsname_r(master.as_raw_fd(), name.as_mut_ptr(), name.len()) != 0 {
            return Err(std::io::Error::last_os_error()).context("ptsname");
        }
        let slave = libc::open(
            name.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        );
        if slave < 0 {
            return Err(std::io::Error::last_os_error()).context("open PTY slave");
        }
        let slave = OwnedFd::from_raw_fd(slave);
        set_window_size(master.as_raw_fd(), cols.max(1), rows.max(1))?;
        Ok((master, slave))
    }
}

fn pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: pipe2 initializes both descriptors on success.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: both descriptors are fresh and owned here.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn os_error() -> std::io::Error {
    std::io::Error::last_os_error()
}

/// Write the user-namespace maps of a child that has unshared and reported
/// its PID, then release it. Runs in the shim, which holds CAP_SETUID and
/// CAP_SETGID in the parent namespace.
fn map_user_namespace(report: OwnedFd, release: OwnedFd) {
    use std::io::{Read, Write};
    let mut report = std::fs::File::from(report);
    let mut release = std::fs::File::from(release);
    let mut pid = [0u8; 4];
    if report.read_exact(&mut pid).is_err() {
        return;
    }
    let pid = i32::from_ne_bytes(pid);
    let map = format!("0 {PRIVILEGED_BASE_ID} {PRIVILEGED_ID_RANGE}\n");
    let mapped = ["uid_map", "gid_map"].iter().all(|file| {
        std::fs::write(format!("/proc/{pid}/{file}"), &map)
            .inspect_err(|error| eprintln!("sandbox-shim: write {file} for {pid}: {error}"))
            .is_ok()
    });
    let _ = release.write_all(&[u8::from(mapped)]);
}

/// Paths the child needs between fork and exec, prepared before forking so
/// the child performs no allocation.
struct RootPlan {
    root: CString,
    binds: Vec<(CString, CString)>,
    ca_source: CString,
    ca_target: CString,
    workdir: CString,
    diagnostics: Option<OwnedFd>,
}

impl RootPlan {
    fn new(workdir: &str) -> Result<Self> {
        let under = |path: &str| CString::new(format!("{WORKLOAD_ROOT}{path}"));
        // SAFETY: duplicating our own stderr; the copy is owned below.
        let diagnostics = unsafe { libc::fcntl(2, libc::F_DUPFD_CLOEXEC, 3) };
        Ok(Self {
            root: CString::new(WORKLOAD_ROOT)?,
            binds: ["/proc", "/sys", "/dev"]
                .iter()
                .map(|path| Ok((CString::new(*path)?, under(path)?)))
                .collect::<Result<_, std::ffi::NulError>>()?,
            ca_source: CString::new(SHIM_TLS_DIR)?,
            ca_target: under(WORKLOAD_TLS_DIR)?,
            workdir: CString::new(workdir)?,
            // SAFETY: a fresh descriptor, or -1 which is never used.
            diagnostics: (diagnostics >= 0).then(|| unsafe { OwnedFd::from_raw_fd(diagnostics) }),
        })
    }

    /// Fail with the current errno, naming the step on the shim's stderr.
    /// Async-signal-safe: one write of static bytes.
    fn check(&self, ok: bool, step: &'static [u8]) -> std::io::Result<()> {
        if ok {
            return Ok(());
        }
        let error = os_error();
        self.note(step);
        Err(error)
    }

    fn note(&self, step: &'static [u8]) {
        if let Some(fd) = &self.diagnostics {
            // SAFETY: write of a static buffer to an owned descriptor.
            unsafe { libc::write(fd.as_raw_fd(), step.as_ptr().cast(), step.len()) };
        }
    }

    /// Install the workload hardening filter as the last step before exec,
    /// on top of the inherited networking listener.
    fn harden(&self, hardening: &mut Option<ChildHardeningProgram>) -> std::io::Result<()> {
        if let Some(program) = hardening {
            program.install().inspect_err(|_| {
                self.note(b"sandbox-shim child: install workload hardening failed\n");
            })?;
        }
        Ok(())
    }

    /// Switch the calling child, already in a private mount namespace, to
    /// the workload root. Shim paths are absent afterwards. Mount effects
    /// stay in the child's namespace; in privileged mode they also run with
    /// only user-namespace credentials.
    ///
    /// # Safety
    /// Only async-signal-safe syscalls; call between fork and exec.
    unsafe fn enter(&self) -> std::io::Result<()> {
        unsafe {
            let null = std::ptr::null();
            let mount = |source: *const libc::c_char, target: *const libc::c_char, flags| {
                libc::mount(source, target, null, flags, null.cast()) == 0
            };
            self.check(
                mount(null, c"/".as_ptr(), libc::MS_REC | libc::MS_PRIVATE),
                b"sandbox-shim child: make mounts private failed\n",
            )?;
            // Mounts inherited across CLONE_NEWUSER are locked, and pivot_root
            // refuses a locked new root. Bind the workload root onto itself in
            // this namespace and pivot into that bind, as rootless runtimes do.
            self.check(
                mount(
                    self.root.as_ptr(),
                    self.root.as_ptr(),
                    libc::MS_BIND | libc::MS_REC,
                ),
                b"sandbox-shim child: self-bind workload root failed\n",
            )?;
            for (source, target) in &self.binds {
                self.check(
                    mount(
                        source.as_ptr(),
                        target.as_ptr(),
                        libc::MS_BIND | libc::MS_REC,
                    ),
                    b"sandbox-shim child: bind /proc, /sys or /dev failed\n",
                )?;
            }
            libc::mkdir(self.ca_target.as_ptr(), 0o755);
            self.check(
                mount(
                    self.ca_source.as_ptr(),
                    self.ca_target.as_ptr(),
                    libc::MS_BIND,
                ),
                b"sandbox-shim child: bind CA directory failed\n",
            )?;
            // Keep the flags a user namespace may not clear.
            self.check(
                mount(
                    null,
                    self.ca_target.as_ptr(),
                    libc::MS_BIND
                        | libc::MS_REMOUNT
                        | libc::MS_RDONLY
                        | libc::MS_NOSUID
                        | libc::MS_NODEV
                        | libc::MS_NOEXEC,
                ),
                b"sandbox-shim child: remount CA directory read-only failed\n",
            )?;
            self.check(
                libc::chdir(self.root.as_ptr()) == 0
                    && libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".".as_ptr()) == 0,
                b"sandbox-shim child: pivot_root into workload rootfs failed\n",
            )?;
            self.check(
                libc::umount2(c".".as_ptr(), libc::MNT_DETACH) == 0
                    && libc::chdir(c"/".as_ptr()) == 0,
                b"sandbox-shim child: detach shim root failed\n",
            )?;
            Ok(())
        }
    }
}

/// Delegated cgroup v2 subtree for privileged workloads, following the
/// kernel's delegation model: the directory and its `cgroup.procs`,
/// `cgroup.subtree_control` and `cgroup.threads` are owned by the namespace
/// root's guest uid. Workload processes live in its `init` leaf so the
/// delegated root can enable controllers for nested runtimes.
pub struct Delegation {
    dir: PathBuf,
}

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const DELEGATED_CGROUP: &str = "openshell-workload";

impl Delegation {
    pub fn create() -> Result<Self> {
        let root = Path::new(CGROUP_ROOT);
        let controllers = std::fs::read_to_string(root.join("cgroup.controllers"))
            .context("cgroup v2 is not mounted")?;
        for controller in controllers.split_whitespace() {
            // The root cgroup is exempt from the no-internal-process rule.
            let _ = std::fs::write(
                root.join("cgroup.subtree_control"),
                format!("+{controller}"),
            );
        }
        let dir = root.join(DELEGATED_CGROUP);
        std::fs::create_dir_all(dir.join("init"))?;
        for cgroup in [dir.clone(), dir.join("init")] {
            for path in [
                cgroup.clone(),
                cgroup.join("cgroup.procs"),
                cgroup.join("cgroup.subtree_control"),
                cgroup.join("cgroup.threads"),
            ] {
                // gVisor's cgroup v2 emulation has no cgroup.threads.
                if path.ends_with("cgroup.threads") && !path.exists() {
                    continue;
                }
                std::os::unix::fs::chown(&path, Some(PRIVILEGED_BASE_ID), Some(PRIVILEGED_BASE_ID))
                    .with_context(|| format!("delegate {}", path.display()))?;
            }
        }
        Ok(Self { dir })
    }

    /// Kill every process in the delegated subtree, nested containers included.
    pub fn kill_all(&self) -> bool {
        std::fs::write(self.dir.join("cgroup.kill"), "1").is_ok()
    }
}

/// User, mount and (with a delegation) cgroup namespaces shared by every
/// privileged workload process, held open by a minimal `sandbox-shim hold`
/// process. Workload processes join them like `docker exec` joins a container.
pub struct Namespaces {
    user: OwnedFd,
    mount: OwnedFd,
    cgroup: Option<OwnedFd>,
    init_procs: Option<CString>,
    _holder: tokio::process::Child,
}

fn open_namespace(pid: u32, kind: &str) -> Result<OwnedFd> {
    Ok(std::fs::File::open(format!("/proc/{pid}/ns/{kind}"))
        .with_context(|| format!("open {kind} namespace of {pid}"))?
        .into())
}

/// Write "0" (the caller) to a `cgroup.procs` file.
///
/// # Safety
/// Only async-signal-safe syscalls; call between fork and exec.
unsafe fn join_cgroup(plan: &RootPlan, procs: &CString) -> std::io::Result<()> {
    unsafe {
        let fd = libc::open(procs.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        let ok = fd >= 0 && libc::write(fd, c"0".as_ptr().cast(), 1) == 1;
        if fd >= 0 {
            libc::close(fd);
        }
        plan.check(ok, b"sandbox-shim child: join delegated cgroup failed\n")
    }
}

impl Namespaces {
    pub async fn create(
        delegation: Option<&Delegation>,
        launcher: Option<&WorkloadLauncher>,
    ) -> Result<Self> {
        let plan = RootPlan::new("/")?;
        let mut hardening = hardening(launcher)?;
        let cgroup_paths = match delegation {
            Some(delegation) => Some((
                CString::new(
                    delegation
                        .dir
                        .join("cgroup.procs")
                        .into_os_string()
                        .into_vec(),
                )?,
                CString::new(format!("{CGROUP_ROOT}/init/cgroup.procs"))?,
                CString::new(CGROUP_ROOT)?,
            )),
            None => None,
        };
        let init_procs = match delegation {
            Some(delegation) => Some(CString::new(
                delegation
                    .dir
                    .join("init/cgroup.procs")
                    .into_os_string()
                    .into_vec(),
            )?),
            None => None,
        };
        let mut command = std::process::Command::new("/proc/self/exe");
        command
            .arg("hold")
            .env_clear()
            .current_dir("/")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let (report_read, report_write) = pipe()?;
        let (release_read, release_write) = pipe()?;
        let report_fd = report_write.as_raw_fd();
        let release_fd = release_read.as_raw_fd();
        let mapper = std::thread::spawn(move || map_user_namespace(report_read, release_write));
        let flags = libc::CLONE_NEWUSER
            | libc::CLONE_NEWNS
            | if cgroup_paths.is_some() {
                libc::CLONE_NEWCGROUP
            } else {
                0
            };
        use std::os::unix::process::CommandExt;
        // SAFETY: only async-signal-safe syscalls run between fork and exec.
        unsafe {
            command.pre_exec(move || {
                // Enter the delegated root first so it becomes the cgroup
                // namespace root, then move to its leaf.
                if let Some((procs, _, _)) = &cgroup_paths {
                    join_cgroup(&plan, procs)?;
                }
                plan.check(
                    libc::unshare(flags) == 0,
                    b"sandbox-shim child: unshare workload namespaces failed\n",
                )?;
                let pid = libc::getpid().to_ne_bytes();
                plan.check(
                    libc::write(report_fd, pid.as_ptr().cast(), 4) == 4,
                    b"sandbox-shim child: report pid failed\n",
                )?;
                libc::close(report_fd);
                let mut mapped = 0u8;
                plan.check(
                    libc::read(release_fd, (&raw mut mapped).cast(), 1) == 1 && mapped == 1,
                    b"sandbox-shim child: user namespace mapping failed\n",
                )?;
                plan.check(
                    libc::setresgid(0, 0, 0) == 0
                        && libc::setgroups(0, std::ptr::null()) == 0
                        && libc::setresuid(0, 0, 0) == 0,
                    b"sandbox-shim child: become namespace root failed\n",
                )?;
                plan.enter()?;
                if let Some((_, leaf, mount_point)) = &cgroup_paths {
                    // The kernel refuses a cgroup2 mount directly on the
                    // inherited (locked) cgroup2 mount; cover it first.
                    plan.check(
                        libc::mount(
                            c"tmpfs".as_ptr(),
                            mount_point.as_ptr(),
                            c"tmpfs".as_ptr(),
                            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                            c"size=64k,mode=755".as_ptr().cast(),
                        ) == 0,
                        b"sandbox-shim child: cover inherited cgroup mount failed\n",
                    )?;
                    plan.check(
                        libc::mount(
                            c"cgroup2".as_ptr(),
                            mount_point.as_ptr(),
                            c"cgroup2".as_ptr(),
                            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                            std::ptr::null(),
                        ) == 0,
                        b"sandbox-shim child: mount delegated cgroup2 failed\n",
                    )?;
                    join_cgroup(&plan, leaf)?;
                }
                plan.check(libc::setsid() >= 0, b"sandbox-shim child: setsid failed\n")?;
                // The holder shares the workload's credentials; it gets the
                // same filters so it is no unfiltered path out.
                plan.harden(&mut hardening)
            });
        }
        // The child blocks in pre_exec until the mapper thread releases it,
        // and spawn blocks until exec, so spawn off the async workers.
        let spawned = launch(command, launcher.cloned()).await;
        drop(report_write);
        drop(release_read);
        let _ = mapper.join();
        let holder = spawned.context("start namespace holder")?;
        let pid = holder.id().context("namespace holder exited")?;
        Ok(Self {
            user: open_namespace(pid, "user")?,
            mount: open_namespace(pid, "mnt")?,
            cgroup: match delegation {
                Some(_) => Some(open_namespace(pid, "cgroup")?),
                None => None,
            },
            init_procs,
            _holder: holder,
        })
    }
}

/// How a workload process is placed.
pub enum Placement<'a> {
    Nonprivileged,
    Privileged(&'a Namespaces),
}

/// Prebuilt hardening for children of a mediated launcher; none otherwise.
fn hardening(launcher: Option<&WorkloadLauncher>) -> Result<Option<ChildHardeningProgram>> {
    launcher
        .map(|_| openshell_sandbox::linux::child_seccomp::prepare_namespaced())
        .transpose()
        .context("prepare workload hardening")
}

/// Fork and exec `command`. With a launcher, the fork happens on its
/// filtered thread so the child inherits the networking listener.
async fn launch(
    command: std::process::Command,
    launcher: Option<WorkloadLauncher>,
) -> Result<tokio::process::Child> {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let spawn = move || {
            let _guard = handle.enter();
            tokio::process::Command::from(command).spawn()
        };
        match launcher {
            Some(launcher) => launcher.execute(spawn).and_then(|spawned| spawned),
            None => spawn(),
        }
    })
    .await?
    .context("spawn workload process")
}

pub async fn spawn(
    id: String,
    spec: SpawnSpec,
    placement: Placement<'_>,
    launcher: Option<&WorkloadLauncher>,
) -> Result<Arc<Process>> {
    let plan = RootPlan::new(&spec.workdir)?;
    let mut hardening = hardening(launcher)?;
    let mut command = std::process::Command::new(&spec.program);
    command
        .args(&spec.args)
        .env_clear()
        .envs(spec.env.iter().map(|(k, v)| (k, v)))
        // Resolved after entering the workload root; std applies this before pre_exec.
        .current_dir("/");
    let pty = spec.pty.is_some();
    let master = match spec.pty {
        Some((cols, rows)) => {
            let (master, slave) = open_pty(cols, rows)?;
            command
                .stdin(slave.try_clone()?)
                .stdout(slave.try_clone()?)
                .stderr(slave);
            Some(master)
        }
        None => {
            command
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            None
        }
    };
    use std::os::unix::process::CommandExt;
    match placement {
        Placement::Nonprivileged => {
            let id = crate::launch::NONPRIVILEGED_ID;
            // SAFETY: only async-signal-safe syscalls run between fork and exec.
            unsafe {
                command.pre_exec(move || {
                    plan.check(
                        libc::unshare(libc::CLONE_NEWNS) == 0,
                        b"sandbox-shim child: unshare mount namespace failed\n",
                    )?;
                    plan.enter()?;
                    plan.check(
                        libc::setgroups(0, std::ptr::null()) == 0
                            && libc::setresgid(id, id, id) == 0
                            && libc::setresuid(id, id, id) == 0
                            && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0,
                        b"sandbox-shim child: drop to workload uid failed\n",
                    )?;
                    finish_child(&plan, pty)?;
                    plan.harden(&mut hardening)
                });
            }
        }
        Placement::Privileged(namespaces) => {
            let user = namespaces.user.as_raw_fd();
            let mount = namespaces.mount.as_raw_fd();
            let cgroup = namespaces.cgroup.as_ref().map(AsRawFd::as_raw_fd);
            let init_procs = namespaces.init_procs.clone();
            // SAFETY: only async-signal-safe syscalls run between fork and exec.
            unsafe {
                command.pre_exec(move || {
                    if let Some(procs) = &init_procs {
                        join_cgroup(&plan, procs)?;
                    }
                    plan.check(
                        libc::setns(user, libc::CLONE_NEWUSER) == 0
                            && libc::setns(mount, libc::CLONE_NEWNS) == 0
                            && cgroup.is_none_or(|fd| libc::setns(fd, libc::CLONE_NEWCGROUP) == 0),
                        b"sandbox-shim child: join workload namespaces failed\n",
                    )?;
                    plan.check(
                        libc::setresgid(0, 0, 0) == 0
                            && libc::setgroups(0, std::ptr::null()) == 0
                            && libc::setresuid(0, 0, 0) == 0,
                        b"sandbox-shim child: become namespace root failed\n",
                    )?;
                    finish_child(&plan, pty)?;
                    plan.harden(&mut hardening)
                });
            }
        }
    }
    let child = launch(command, launcher.cloned()).await?;
    Ok(supervise(id, child, master, pty))
}

/// # Safety
/// Only async-signal-safe syscalls; call between fork and exec.
unsafe fn finish_child(plan: &RootPlan, pty: bool) -> std::io::Result<()> {
    unsafe {
        plan.check(libc::setsid() >= 0, b"sandbox-shim child: setsid failed\n")?;
        plan.check(
            !pty || libc::ioctl(0, libc::TIOCSCTTY, 0) == 0,
            b"sandbox-shim child: set controlling terminal failed\n",
        )?;
        plan.check(
            libc::chdir(plan.workdir.as_ptr()) == 0,
            b"sandbox-shim child: chdir to workdir failed\n",
        )
    }
}

/// Block until `pid` has exited, leaving it unreaped so its PID (and process
/// group number) cannot be reused yet.
fn wait_exited_unreaped(pid: i32) {
    loop {
        // SAFETY: waitid fills a zeroed siginfo for our own child.
        let result = unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if result == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return;
        }
    }
}

fn supervise(
    id: String,
    mut child: tokio::process::Child,
    master: Option<OwnedFd>,
    pty: bool,
) -> Arc<Process> {
    let pid = child.id().map_or(0, |pid| pid as i32);
    let output = Arc::new(Output::default());
    let mut readers = Vec::new();
    let stdin: Option<Writer> = match &master {
        Some(master) => {
            let reader = master.try_clone().expect("dup PTY master");
            let writer = master.try_clone().expect("dup PTY master");
            readers.push(pump(
                tokio::fs::File::from_std(std::fs::File::from(reader)),
                openshell_sandbox_backend::boundary_protocol::STREAM_STDOUT,
                output.clone(),
            ));
            Some(Box::new(tokio::fs::File::from_std(std::fs::File::from(
                writer,
            ))))
        }
        None => {
            if let Some(stdout) = child.stdout.take() {
                readers.push(pump(
                    stdout,
                    openshell_sandbox_backend::boundary_protocol::STREAM_STDOUT,
                    output.clone(),
                ));
            }
            if let Some(stderr) = child.stderr.take() {
                readers.push(pump(
                    stderr,
                    openshell_sandbox_backend::boundary_protocol::STREAM_STDERR,
                    output.clone(),
                ));
            }
            child.stdin.take().map(|stdin| Box::new(stdin) as Writer)
        }
    };
    let process = Arc::new(Process {
        id,
        pty,
        pid,
        reaped: Mutex::new(false),
        output: output.clone(),
        stdin: tokio::sync::Mutex::new(stdin),
        status: watch::channel(None).0,
        master,
    });
    let watcher = process.clone();
    tokio::spawn(async move {
        use std::os::unix::process::ExitStatusExt;
        let _ = tokio::task::spawn_blocking(move || wait_exited_unreaped(pid)).await;
        // Signals are sent only while this flag is false, i.e. while the PID
        // still names our child (alive or zombie).
        *watcher.reaped.lock().unwrap() = true;
        let status = match child.wait().await {
            Ok(status) => match (status.code(), status.signal()) {
                (Some(code), _) => ExitStatusWire::Exited(code),
                (None, Some(signal)) => ExitStatusWire::Signaled(signal),
                (None, None) => ExitStatusWire::Exited(1),
            },
            Err(_) => ExitStatusWire::Exited(1),
        };
        // Background descendants may hold the output open; bound the drain.
        let _ = tokio::time::timeout(OUTPUT_DRAIN_GRACE, async {
            for reader in readers {
                let _ = reader.await;
            }
        })
        .await;
        watcher.stdin.lock().await.take();
        output.close();
        watcher.status.send_replace(Some(status));
    });
    process
}

fn pump(
    mut reader: impl AsyncRead + Unpin + Send + 'static,
    channel: u8,
    output: Arc<Output>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = vec![0; READ_CHUNK];
        // A PTY master reports EIO once the last slave closes.
        while let Ok(read) = reader.read(&mut buffer).await {
            if read == 0 {
                break;
            }
            output.push(channel, &buffer[..read]);
        }
    })
}

/// Guest UIDs that belong to the workload under `privilege`.
pub fn workload_uid(privilege: Privilege, uid: u32) -> bool {
    match privilege {
        Privilege::Nonprivileged => uid == crate::launch::NONPRIVILEGED_ID,
        Privilege::Privileged => {
            (PRIVILEGED_BASE_ID..PRIVILEGED_BASE_ID + PRIVILEGED_ID_RANGE).contains(&uid)
        }
    }
}

/// SIGKILL every guest process running as a workload UID, including
/// descendants that left their process group. Returns how many were signalled.
pub fn kill_workload(privilege: Privilege) -> usize {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return 0;
    };
    let mut killed = 0;
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
        else {
            continue;
        };
        let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
            continue;
        };
        let uid = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|ids| ids.split_whitespace().next())
            .and_then(|uid| uid.parse::<u32>().ok());
        if uid.is_some_and(|uid| workload_uid(privilege, uid)) {
            // SAFETY: plain syscall on a PID read from procfs.
            if unsafe { libc::kill(pid, libc::SIGKILL) } == 0 {
                killed += 1;
            }
        }
    }
    killed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_window_drops_oldest_chunks() {
        let output = Output::default();
        let big = vec![0u8; RETAINED_OUTPUT_BYTES / 2 + 1];
        output.push(1, &big);
        output.push(2, &big);
        output.push(1, b"tail");
        let (chunks, next, closed) = output.read_from(0);
        assert_eq!(next, 3);
        assert!(!closed);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks.last().unwrap().bytes, b"tail");
    }

    #[test]
    fn workload_uid_ranges() {
        assert!(workload_uid(Privilege::Nonprivileged, 10_001));
        assert!(!workload_uid(Privilege::Nonprivileged, 0));
        assert!(workload_uid(Privilege::Privileged, 100_000));
        assert!(workload_uid(Privilege::Privileged, 165_535));
        assert!(!workload_uid(Privilege::Privileged, 165_536));
        assert!(!workload_uid(Privilege::Privileged, 0));
    }
}
