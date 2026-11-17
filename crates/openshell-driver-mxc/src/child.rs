// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Start a sandbox generation's processes inside their job object, atomically.
//!
//! The job is named in the `PROC_THREAD_ATTRIBUTE_JOB_LIST` attribute of the
//! `CreateProcessW` call, so the new process is a member of its job from the moment
//! it exists. There is no window between creating a process and assigning it to the
//! job in which a hard-killed driver could leave the process behind. The standard
//! library and tokio offer no stable way to set that attribute, so the processes the
//! driver starts for a generation (the host supervisor and `wxc-exec`) are created
//! here.
//!
//! [`ChildCommand`] describes the process in the same terms the driver already used
//! for `tokio::process::Command`, and [`GenerationChild`] offers the subset of
//! `tokio::process::Child` the driver relies on: `id`, `raw_handle`, `wait`,
//! `kill`, and async `stdout`/`stderr`. A child is killed when its
//! [`GenerationChild`] is dropped, like the former `kill_on_drop(true)`.
//!
//! Only the three standard handles are inherited (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`),
//! so no other handle of the host, such as a listening socket, leaks into a sandbox
//! process.

// Process creation is Win32 FFI and needs `unsafe`; it is confined to this module.
#![allow(unsafe_code)]
// `pub(crate)` documents what the driver may use; this module is private.
#![allow(clippy::redundant_pub_crate)]

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString, c_void};
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::RawHandle;
use std::os::windows::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio::sync::watch;
use windows::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED,
};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING, PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND,
};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Pipes::{
    CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetExitCodeProcess, INFINITE,
    InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_CREATION_FLAGS,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};
use windows::core::{PCWSTR, PWSTR};

/// What a standard stream of a new process is connected to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildStdio {
    /// The `NUL` device.
    Null,
    /// A pipe whose parent end is exposed on the [`GenerationChild`].
    Piped,
    /// The same stream as the host process.
    Inherit,
}

/// A process to start inside a generation's job.
#[derive(Clone, Debug)]
pub struct ChildCommand {
    program: OsString,
    args: Vec<OsString>,
    raw_args: Option<OsString>,
    envs: Vec<(OsString, OsString)>,
    stdin: ChildStdio,
    stdout: ChildStdio,
    stderr: ChildStdio,
}

impl ChildCommand {
    pub(crate) fn new(program: impl AsRef<OsStr>) -> Self {
        Self {
            program: program.as_ref().to_os_string(),
            args: Vec::new(),
            raw_args: None,
            envs: Vec::new(),
            stdin: ChildStdio::Inherit,
            stdout: ChildStdio::Inherit,
            stderr: ChildStdio::Inherit,
        }
    }

    /// Append an argument; it is quoted so the new process parses it back unchanged.
    pub(crate) fn arg(&mut self, arg: impl AsRef<OsStr>) -> &mut Self {
        self.args.push(arg.as_ref().to_os_string());
        self
    }

    #[cfg(test)]
    pub(crate) fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        for arg in args {
            self.arg(arg);
        }
        self
    }

    /// Append already-encoded arguments to the command line exactly as given.
    pub(crate) fn raw_arg(&mut self, arg: impl AsRef<OsStr>) -> &mut Self {
        self.raw_args = Some(arg.as_ref().to_os_string());
        self
    }

    /// Set an environment variable for the new process, on top of the host's.
    pub(crate) fn env(&mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> &mut Self {
        self.envs
            .push((key.as_ref().to_os_string(), value.as_ref().to_os_string()));
        self
    }

    pub(crate) fn stdin(&mut self, stdio: ChildStdio) -> &mut Self {
        self.stdin = stdio;
        self
    }

    pub(crate) fn stdout(&mut self, stdio: ChildStdio) -> &mut Self {
        self.stdout = stdio;
        self
    }

    pub(crate) fn stderr(&mut self, stdio: ChildStdio) -> &mut Self {
        self.stderr = stdio;
        self
    }

    /// The environment variables set explicitly on this command.
    #[cfg(test)]
    pub(crate) fn get_envs(&self) -> impl Iterator<Item = (&OsStr, &OsStr)> {
        self.envs
            .iter()
            .map(|(k, v)| (k.as_os_str(), v.as_os_str()))
    }
}

/// An owned Win32 handle, closed on drop.
struct OwnedHandle(HANDLE);

// SAFETY: a kernel handle has no thread affinity; every use below is thread-safe.
unsafe impl Send for OwnedHandle {}
// SAFETY: as above.
unsafe impl Sync for OwnedHandle {}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() && !self.0.0.is_null() {
            // SAFETY: the handle is owned and closed exactly once.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

/// A process started inside its generation's job.
///
/// It is killed when dropped if it is still running.
pub struct GenerationChild {
    process: Arc<OwnedHandle>,
    pid: u32,
    exit: watch::Receiver<Option<u32>>,
    /// Parent end of the child's standard input, when it was [`ChildStdio::Piped`].
    /// Held open for the child's lifetime so the child does not see end-of-file; the
    /// driver never writes to it.
    _stdin: Option<NamedPipeServer>,
    pub(crate) stdout: Option<NamedPipeServer>,
    pub(crate) stderr: Option<NamedPipeServer>,
}

/// What the ETW consumer needs from a child to attribute its events.
pub trait ProcessHandle {
    fn id(&self) -> Option<u32>;
    fn raw_handle(&self) -> Option<RawHandle>;
}

impl ProcessHandle for GenerationChild {
    fn id(&self) -> Option<u32> {
        Self::id(self)
    }

    fn raw_handle(&self) -> Option<RawHandle> {
        Self::raw_handle(self)
    }
}

impl ProcessHandle for tokio::process::Child {
    fn id(&self) -> Option<u32> {
        Self::id(self)
    }

    fn raw_handle(&self) -> Option<RawHandle> {
        Self::raw_handle(self)
    }
}

impl GenerationChild {
    /// The process ID. Always present; the `Option` mirrors `tokio::process::Child::id`
    /// so the ETW consumer can take either through [`ProcessHandle`].
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn id(&self) -> Option<u32> {
        Some(self.pid)
    }

    /// The process handle, valid for as long as this value lives. Always present; see
    /// [`GenerationChild::id`].
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn raw_handle(&self) -> Option<RawHandle> {
        Some(self.process.0.0)
    }

    /// Ask the process to end now, without waiting for it.
    pub(crate) fn start_kill(&mut self) -> io::Result<()> {
        if self.exit.borrow().is_some() {
            return Ok(());
        }
        // SAFETY: the handle is owned by `self.process` and valid.
        match unsafe { TerminateProcess(self.process.0, 1) } {
            Ok(()) => Ok(()),
            // Lost a race with the process ending by itself.
            Err(_) if self.exit.borrow().is_some() => Ok(()),
            Err(error) => Err(io::Error::from(error)),
        }
    }

    /// Wait for the process to end. Safe to cancel and to call again.
    pub(crate) async fn wait(&mut self) -> io::Result<ExitStatus> {
        loop {
            let code = *self.exit.borrow();
            if let Some(code) = code {
                return Ok(ExitStatus::from_raw(code));
            }
            self.exit
                .changed()
                .await
                .map_err(|_| io::Error::other("process exit watcher ended unexpectedly"))?;
        }
    }

    /// End the process and wait for it to be gone.
    pub(crate) async fn kill(&mut self) -> io::Result<()> {
        self.start_kill()?;
        self.wait().await.map(|_| ())
    }
}

impl Drop for GenerationChild {
    fn drop(&mut self) {
        let _ = self.start_kill();
    }
}

static PIPE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn inheritable() -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true.into(),
    }
}

fn to_wide(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut wide: Vec<u16> = value.encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a process argument, path or environment entry contains a NUL",
        ));
    }
    wide.push(0);
    Ok(wide)
}

/// Append `arg` quoted so `CommandLineToArgvW` and the C runtime parse it back to `arg`.
fn append_arg(out: &mut Vec<u16>, arg: &OsStr) -> io::Result<()> {
    let wide: Vec<u16> = arg.encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a process argument contains a NUL",
        ));
    }
    let space = u16::from(b' ');
    let tab = u16::from(b'\t');
    let quote = u16::from(b'"');
    let backslash = u16::from(b'\\');
    let needs_quotes = wide.is_empty() || wide.iter().any(|&c| c == space || c == tab);
    if needs_quotes {
        out.push(quote);
    }
    let mut backslashes = 0usize;
    for &c in &wide {
        if c == backslash {
            backslashes += 1;
        } else {
            if c == quote {
                // Double the backslashes before a quote, then escape the quote.
                out.extend(std::iter::repeat_n(backslash, backslashes + 1));
            }
            backslashes = 0;
        }
        out.push(c);
    }
    if needs_quotes {
        // Backslashes at the end would otherwise escape the closing quote.
        out.extend(std::iter::repeat_n(backslash, backslashes));
        out.push(quote);
    }
    Ok(())
}

/// The command line: the quoted program, the quoted arguments, then any raw text.
fn build_command_line(command: &ChildCommand, program: &Path) -> io::Result<Vec<u16>> {
    let mut line: Vec<u16> = Vec::new();
    let program = program.as_os_str();
    if program.encode_wide().any(|c| c == u16::from(b'"')) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "program path contains a quote",
        ));
    }
    // The program is always quoted: its first token is parsed differently from the rest.
    line.push(u16::from(b'"'));
    line.extend(program.encode_wide());
    line.push(u16::from(b'"'));
    for arg in &command.args {
        line.push(u16::from(b' '));
        append_arg(&mut line, arg)?;
    }
    if let Some(raw) = &command.raw_args {
        let raw: Vec<u16> = raw.encode_wide().collect();
        if !raw.is_empty() {
            line.push(u16::from(b' '));
            line.extend(raw);
        }
    }
    if line.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the command line contains a NUL",
        ));
    }
    line.push(0);
    Ok(line)
}

/// Windows compares environment names case-insensitively.
fn env_sort_key(name: &OsStr) -> Vec<u16> {
    char::decode_utf16(name.encode_wide())
        .flat_map(|unit| {
            unit.map_or_else(
                |_| Vec::new(),
                |character| character.to_uppercase().collect::<Vec<_>>(),
            )
        })
        .flat_map(|character| {
            let mut buffer = [0u16; 2];
            character.encode_utf16(&mut buffer).to_vec()
        })
        .collect()
}

/// The new process's environment: the host's, with `overrides` applied, as the
/// sorted UTF-16 block `CreateProcessW` requires.
fn build_env_block(overrides: &[(OsString, OsString)]) -> io::Result<Vec<u16>> {
    let mut merged: BTreeMap<Vec<u16>, (OsString, OsString)> = BTreeMap::new();
    for (name, value) in std::env::vars_os() {
        merged.insert(env_sort_key(&name), (name, value));
    }
    for (name, value) in overrides {
        merged.insert(env_sort_key(name), (name.clone(), value.clone()));
    }
    let mut block: Vec<u16> = Vec::new();
    for (name, value) in merged.values() {
        let entry_start = block.len();
        block.extend(name.encode_wide());
        block.push(u16::from(b'='));
        block.extend(value.encode_wide());
        if block[entry_start..].contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "an environment entry contains a NUL",
            ));
        }
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

/// Find the executable for `program`: as given when it has a directory, otherwise
/// in the `PATH` directories and then the system directory. The current directory
/// is deliberately not searched.
fn resolve_program(program: &OsStr) -> io::Result<PathBuf> {
    let candidates = |base: PathBuf| -> Vec<PathBuf> {
        if base.extension().is_some() {
            vec![base]
        } else {
            let mut with_exe = base.clone().into_os_string();
            with_exe.push(".exe");
            vec![base, PathBuf::from(with_exe)]
        }
    };
    let given = Path::new(program);
    if given.is_absolute() || given.components().count() > 1 {
        return candidates(given.to_path_buf())
            .into_iter()
            .find(|candidate| candidate.is_file())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("program not found: {}", given.display()),
                )
            });
    }
    let mut directories: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect())
        .unwrap_or_default();
    if let Some(root) = std::env::var_os("SystemRoot") {
        directories.push(PathBuf::from(root).join("System32"));
    }
    for directory in directories {
        for candidate in candidates(directory.join(given)) {
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("program not found: {}", given.display()),
    ))
}

/// The child-side handle of one standard stream, plus the parent end if piped.
struct StdioPair {
    child: OwnedHandle,
    parent: Option<NamedPipeServer>,
}

fn open_nul(write: bool) -> io::Result<OwnedHandle> {
    let sa = inheritable();
    let access = if write {
        FILE_GENERIC_WRITE.0
    } else {
        FILE_GENERIC_READ.0
    };
    let name = to_wide(OsStr::new("NUL"))?;
    // SAFETY: `name` is NUL-terminated and outlives the call; `sa` outlives it too.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(name.as_ptr()),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            Some(&raw const sa),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(io::Error::from)?;
    Ok(OwnedHandle(handle))
}

fn inherit_std(which: STD_HANDLE, write: bool) -> io::Result<OwnedHandle> {
    // SAFETY: plain Win32 calls; the duplicate is owned by the returned value.
    unsafe {
        let source = match GetStdHandle(which) {
            Ok(handle) if !handle.is_invalid() && !handle.0.is_null() => handle,
            _ => return open_nul(write),
        };
        let mut duplicate = HANDLE::default();
        let process = GetCurrentProcess();
        match DuplicateHandle(
            process,
            source,
            process,
            &raw mut duplicate,
            0,
            true,
            DUPLICATE_SAME_ACCESS,
        ) {
            Ok(()) => Ok(OwnedHandle(duplicate)),
            // The host's stream is not a duplicable handle (for example no console).
            Err(_) => open_nul(write),
        }
    }
}

/// A pipe with an overlapped parent end (usable by tokio) and an inheritable child end.
/// `child_writes` is true for stdout/stderr, false for stdin.
fn make_pipe(child_writes: bool) -> io::Result<StdioPair> {
    let name = format!(
        r"\\.\pipe\openshell-mxc-{}-{}-{:016x}",
        std::process::id(),
        PIPE_COUNTER.fetch_add(1, Ordering::Relaxed),
        rand::random::<u64>()
    );
    let wide = to_wide(OsStr::new(&name))?;
    let direction = if child_writes {
        PIPE_ACCESS_INBOUND
    } else {
        PIPE_ACCESS_OUTBOUND
    };
    // SAFETY: `wide` is NUL-terminated and outlives the calls; the handles are
    // owned by the values they are stored in and closed once.
    unsafe {
        let server = CreateNamedPipeW(
            PCWSTR(wide.as_ptr()),
            direction | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            64 * 1024,
            64 * 1024,
            0,
            None,
        );
        if server == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let server = OwnedHandle(server);
        let sa = inheritable();
        let access = if child_writes {
            FILE_GENERIC_WRITE.0
        } else {
            FILE_GENERIC_READ.0
        };
        let client = CreateFileW(
            PCWSTR(wide.as_ptr()),
            access,
            FILE_SHARE_MODE(0),
            Some(&raw const sa),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(io::Error::from)?;
        let client = OwnedHandle(client);
        let raw = server.0.0;
        std::mem::forget(server);
        // tokio takes ownership of the overlapped server end; on failure it is ours to close.
        let parent = match NamedPipeServer::from_raw_handle(raw) {
            Ok(parent) => parent,
            Err(error) => {
                let _ = CloseHandle(HANDLE(raw));
                return Err(error);
            }
        };
        Ok(StdioPair {
            child: client,
            parent: Some(parent),
        })
    }
}

fn open_stdio(
    stdio: ChildStdio,
    standard: STD_HANDLE,
    child_writes: bool,
) -> io::Result<StdioPair> {
    match stdio {
        ChildStdio::Null => Ok(StdioPair {
            child: open_nul(child_writes)?,
            parent: None,
        }),
        ChildStdio::Inherit => Ok(StdioPair {
            child: inherit_std(standard, child_writes)?,
            parent: None,
        }),
        ChildStdio::Piped => make_pipe(child_writes),
    }
}

/// A `PROC_THREAD_ATTRIBUTE_LIST`, deleted on drop.
struct AttributeList {
    buffer: Vec<u8>,
}

impl AttributeList {
    fn new(count: u32) -> io::Result<Self> {
        let mut size = 0usize;
        // SAFETY: the first call only reports the size needed; failure is expected.
        let _ = unsafe { InitializeProcThreadAttributeList(None, count, None, &raw mut size) };
        let mut buffer = vec![0u8; size];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(buffer.as_mut_ptr().cast());
        // SAFETY: `buffer` is `size` bytes, as the first call requested.
        unsafe { InitializeProcThreadAttributeList(Some(list), count, None, &raw mut size) }
            .map_err(io::Error::from)?;
        Ok(Self { buffer })
    }

    fn list(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        LPPROC_THREAD_ATTRIBUTE_LIST(self.buffer.as_mut_ptr().cast())
    }

    /// `value` must outlive this list (it is read by `CreateProcessW`).
    fn set<T>(&mut self, attribute: u32, value: &[T]) -> io::Result<()> {
        // SAFETY: `value` is valid for the call and the caller keeps it alive.
        unsafe {
            UpdateProcThreadAttribute(
                self.list(),
                0,
                attribute as usize,
                Some(value.as_ptr().cast::<c_void>()),
                size_of_val(value),
                None,
                None,
            )
        }
        .map_err(io::Error::from)
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: the list was initialised in `new` and is deleted once.
        unsafe { DeleteProcThreadAttributeList(self.list()) };
    }
}

/// Create the process for `command` as a member of `job`.
///
/// Must be called inside a tokio runtime (the pipe ends are registered with it).
pub fn spawn_in_job(job: HANDLE, command: &ChildCommand) -> io::Result<GenerationChild> {
    create(job, command, false).map(|(child, _thread)| child)
}

/// The initial thread of a process created suspended, to resume it.
#[cfg(test)]
pub struct SuspendedThread(OwnedHandle);

#[cfg(test)]
impl SuspendedThread {
    pub(crate) fn resume(self) -> io::Result<()> {
        // SAFETY: the thread handle is valid and owned by `self`.
        if unsafe { windows::Win32::System::Threading::ResumeThread(self.0.0) } == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Like [`spawn_in_job`], but the process is created without starting it, so a test can
/// inspect it before it runs.
#[cfg(test)]
pub fn spawn_suspended_in_job(
    job: HANDLE,
    command: &ChildCommand,
) -> io::Result<(GenerationChild, SuspendedThread)> {
    create(job, command, true).map(|(child, thread)| (child, SuspendedThread(thread)))
}

fn create(
    job: HANDLE,
    command: &ChildCommand,
    suspended: bool,
) -> io::Result<(GenerationChild, OwnedHandle)> {
    let program = resolve_program(&command.program)?;
    let mut command_line = build_command_line(command, &program)?;
    let application = to_wide(program.as_os_str())?;
    let environment = build_env_block(&command.envs)?;

    let StdioPair {
        child: stdin_child,
        parent: stdin_parent,
    } = open_stdio(command.stdin, STD_INPUT_HANDLE, false)?;
    let StdioPair {
        child: stdout_child,
        parent: stdout_parent,
    } = open_stdio(command.stdout, STD_OUTPUT_HANDLE, true)?;
    let StdioPair {
        child: stderr_child,
        parent: stderr_parent,
    } = open_stdio(command.stderr, STD_ERROR_HANDLE, true)?;

    // The inherited-handle list may not contain duplicates.
    let mut inherited: Vec<HANDLE> = vec![stdin_child.0];
    for handle in [stdout_child.0, stderr_child.0] {
        if !inherited.contains(&handle) {
            inherited.push(handle);
        }
    }
    let jobs = [job];
    let mut attributes = AttributeList::new(2)?;
    attributes.set(PROC_THREAD_ATTRIBUTE_JOB_LIST, &jobs)?;
    attributes.set(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &inherited)?;

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>()).unwrap_or(0);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdin_child.0;
    startup.StartupInfo.hStdOutput = stdout_child.0;
    startup.StartupInfo.hStdError = stderr_child.0;
    startup.lpAttributeList = attributes.list();

    let mut flags: PROCESS_CREATION_FLAGS =
        EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT;
    if suspended {
        flags |= CREATE_SUSPENDED;
    }
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: every pointer refers to a value that outlives the call; the attribute
    // list, handle arrays and strings are kept alive until after it returns.
    unsafe {
        CreateProcessW(
            PCWSTR(application.as_ptr()),
            Some(PWSTR(command_line.as_mut_ptr())),
            None,
            None,
            true,
            flags,
            Some(environment.as_ptr().cast::<c_void>()),
            PCWSTR::null(),
            &raw const startup.StartupInfo,
            &raw mut info,
        )
    }
    .map_err(|error| {
        io::Error::other(format!(
            "create process {} in its sandbox job: {error}",
            program.display()
        ))
    })?;
    drop(attributes);

    let process = Arc::new(OwnedHandle(info.hProcess));
    let thread = OwnedHandle(info.hThread);
    // The new process has its own copies of the child ends; close ours now so a reader
    // sees end-of-file when the process ends.
    drop((stdin_child, stdout_child, stderr_child));

    let (sender, receiver) = watch::channel(None);
    let watched = Arc::clone(&process);
    let spawned = std::thread::Builder::new()
        .name(format!("mxc-wait-{}", info.dwProcessId))
        .spawn(move || {
            // SAFETY: `watched` keeps the process handle valid for the whole wait.
            let mut code = 0u32;
            unsafe {
                if WaitForSingleObject(watched.0, INFINITE) != WAIT_FAILED {
                    let _ = GetExitCodeProcess(watched.0, &raw mut code);
                }
            }
            let _ = sender.send(Some(code));
        });
    if let Err(error) = spawned {
        // SAFETY: the process handle is valid; end the process nobody can watch.
        let _ = unsafe { TerminateProcess(process.0, 1) };
        return Err(error);
    }

    let child = GenerationChild {
        process,
        pid: info.dwProcessId,
        exit: receiver,
        _stdin: stdin_parent,
        stdout: stdout_parent,
        stderr: stderr_parent,
    };
    Ok((child, thread))
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use std::time::Duration;

    use tokio::io::AsyncReadExt as _;
    use windows::Win32::Foundation::{HLOCAL, LocalFree, WAIT_TIMEOUT};
    use windows::Win32::Storage::FileSystem::CREATE_NEW;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE};
    use windows::Win32::UI::Shell::CommandLineToArgvW;

    use super::*;
    use crate::job::GenerationJob;

    fn quiet(program: &str, args: &[&str]) -> ChildCommand {
        let mut command = ChildCommand::new(program);
        command
            .args(args)
            .stdin(ChildStdio::Null)
            .stdout(ChildStdio::Null)
            .stderr(ChildStdio::Null);
        command
    }

    fn is_alive(pid: u32) -> bool {
        // SAFETY: plain Win32 calls; the handle is closed before returning.
        unsafe {
            let Ok(handle) = OpenProcess(PROCESS_SYNCHRONIZE, false, pid) else {
                return false;
            };
            let alive = WaitForSingleObject(handle, 0) == WAIT_TIMEOUT;
            let _ = CloseHandle(handle);
            alive
        }
    }

    /// Split a command line the way Windows does for every ordinary program.
    fn windows_argv(line: &[u16]) -> Vec<OsString> {
        let mut count = 0i32;
        // SAFETY: `line` is NUL-terminated; the returned array is freed once.
        unsafe {
            let argv = CommandLineToArgvW(PCWSTR(line.as_ptr()), &raw mut count);
            assert!(!argv.is_null(), "CommandLineToArgvW failed");
            let parsed = (0..usize::try_from(count).unwrap())
                .map(|i| {
                    let pointer = (*argv.add(i)).0;
                    let mut len = 0;
                    while *pointer.add(len) != 0 {
                        len += 1;
                    }
                    OsString::from_wide(std::slice::from_raw_parts(pointer, len))
                })
                .collect();
            let _ = LocalFree(Some(HLOCAL(argv.cast())));
            parsed
        }
    }

    use std::os::windows::ffi::OsStringExt as _;

    #[test]
    fn command_line_round_trips_through_the_windows_parser() {
        let tricky = [
            "",
            "plain",
            "with space",
            "tab\there",
            r#"a"b"#,
            r"a\b",
            r"ends with backslash\",
            r"ends with backslashes\\",
            r"\\server\share\file",
            r#"quote then backslash \" end"#,
            r"\",
            r#"say "hello" now"#,
            r"C:\Program Files\Agent\agent.exe",
            "unicode é 日本語",
        ];
        let program = PathBuf::from(r"C:\Program Files\Host\tool.exe");
        let mut command = ChildCommand::new(&program);
        for arg in tricky {
            command.arg(arg);
        }
        let line = build_command_line(&command, &program).expect("command line");
        let parsed = windows_argv(&line);
        let expected: Vec<OsString> = std::iter::once(program.into_os_string())
            .chain(tricky.iter().map(OsString::from))
            .collect();
        assert_eq!(parsed, expected);
    }

    #[test]
    fn raw_arguments_are_appended_exactly() {
        let program = PathBuf::from(r"C:\x\tool.exe");
        let mut command = ChildCommand::new(&program);
        command.arg("one").raw_arg(r#"two "three four" /s"#);
        let line = build_command_line(&command, &program).expect("command line");
        assert_eq!(
            String::from_utf16_lossy(&line[..line.len() - 1]),
            r#""C:\x\tool.exe" one two "three four" /s"#
        );
    }

    #[test]
    fn nul_in_an_argument_is_rejected() {
        let program = PathBuf::from(r"C:\x\tool.exe");
        let mut command = ChildCommand::new(&program);
        command.arg(OsString::from_wide(&[u16::from(b'a'), 0, u16::from(b'b')]));
        assert!(build_command_line(&command, &program).is_err());
    }

    #[test]
    fn environment_block_is_sorted_and_applies_overrides() {
        let overrides = vec![
            (OsString::from("Openshell_B"), OsString::from("2")),
            (OsString::from("OPENSHELL_a"), OsString::from("1")),
            // Same name as the first, different case: the later value replaces it.
            (OsString::from("openshell_b"), OsString::from("3")),
        ];
        let block = build_env_block(&overrides).expect("block");
        assert!(block.ends_with(&[0, 0]), "the block ends with a double NUL");
        let entries: Vec<String> = block
            .split(|&unit| unit == 0)
            .filter(|entry| !entry.is_empty())
            .map(String::from_utf16_lossy)
            .collect();
        let ours: Vec<&String> = entries
            .iter()
            .filter(|entry| entry.to_ascii_lowercase().starts_with("openshell_"))
            .collect();
        assert_eq!(ours, vec!["OPENSHELL_a=1", "openshell_b=3"]);
        let keys: Vec<String> = entries
            .iter()
            .map(|entry| entry.split('=').next().unwrap_or("").to_uppercase())
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(
            keys, sorted,
            "entries must be sorted by name, case-insensitively"
        );
    }

    #[tokio::test]
    async fn exit_status_is_reported() {
        let job = GenerationJob::new().expect("job");
        let mut child = job
            .spawn(&quiet("cmd.exe", &["/c", "exit 7"]))
            .expect("spawn");
        let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
            .await
            .expect("exited")
            .unwrap();
        assert_eq!(status.code(), Some(7));
        // Waiting again returns the same answer.
        assert_eq!(child.wait().await.unwrap().code(), Some(7));
    }

    #[tokio::test]
    async fn piped_output_is_readable_until_the_child_exits() {
        let job = GenerationJob::new().expect("job");
        let mut command = ChildCommand::new("cmd.exe");
        command
            .args(["/c", "echo out& echo err 1>&2"])
            .stdin(ChildStdio::Null)
            .stdout(ChildStdio::Piped)
            .stderr(ChildStdio::Piped);
        let mut child = job.spawn(&command).expect("spawn");
        let mut stdout = child.stdout.take().expect("stdout");
        let mut stderr = child.stderr.take().expect("stderr");
        let (mut out, mut err) = (String::new(), String::new());
        tokio::time::timeout(Duration::from_secs(10), async {
            let _ = stdout.read_to_string(&mut out).await;
            let _ = stderr.read_to_string(&mut err).await;
        })
        .await
        .expect("both streams reach end of file when the child exits");
        assert_eq!(out.trim(), "out");
        assert_eq!(err.trim(), "err");
        assert!(child.wait().await.unwrap().success());
    }

    #[tokio::test]
    async fn environment_overrides_reach_the_child() {
        let job = GenerationJob::new().expect("job");
        let mut command = ChildCommand::new("cmd.exe");
        command
            .args(["/c", "echo %OPENSHELL_CHILD_TEST%"])
            .env("OPENSHELL_CHILD_TEST", "value with spaces")
            .stdin(ChildStdio::Null)
            .stdout(ChildStdio::Piped)
            .stderr(ChildStdio::Null);
        let mut child = job.spawn(&command).expect("spawn");
        let mut out = String::new();
        let _ = child.stdout.take().unwrap().read_to_string(&mut out).await;
        assert_eq!(out.trim(), "value with spaces");
    }

    #[tokio::test]
    async fn a_missing_program_is_reported() {
        let job = GenerationJob::new().expect("job");
        let error = job
            .spawn(&quiet("definitely-not-a-real-binary", &[]))
            .err()
            .expect("must fail");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[tokio::test]
    async fn kill_ends_the_process_and_wait_reports_it() {
        let job = GenerationJob::new().expect("job");
        let mut child = job
            .spawn(&quiet("cmd.exe", &["/c", "ping -n 30 127.0.0.1 >nul"]))
            .expect("spawn");
        tokio::time::timeout(Duration::from_secs(10), child.kill())
            .await
            .expect("killed")
            .unwrap();
        assert!(!is_alive(child.id().unwrap()));
        // Killing an already-dead process is not an error.
        child.start_kill().unwrap();
    }

    #[tokio::test]
    async fn dropping_a_child_kills_it() {
        let job = GenerationJob::new().expect("job");
        let child = job
            .spawn(&quiet("cmd.exe", &["/c", "ping -n 30 127.0.0.1 >nul"]))
            .expect("spawn");
        let pid = child.id().unwrap();
        assert!(is_alive(pid));
        drop(child);
        for _ in 0..100 {
            if !is_alive(pid) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("the dropped child is still running");
    }

    /// An inheritable handle with exclusive access: while any other process holds a copy
    /// the file cannot be deleted.
    fn open_exclusive_inheritable(path: &Path) -> HANDLE {
        let sa = inheritable();
        let name = to_wide(path.as_os_str()).unwrap();
        // SAFETY: `name` and `sa` outlive the call.
        unsafe {
            CreateFileW(
                PCWSTR(name.as_ptr()),
                FILE_GENERIC_WRITE.0,
                FILE_SHARE_MODE(0),
                Some(&raw const sa),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        }
        .expect("create inheritable file")
    }

    /// Only the standard handles may reach a sandbox process. A handle the host holds
    /// (here an inheritable file handle) must not be inherited, as the host's listening
    /// socket once was. The control shows the test can detect an inherited handle.
    #[tokio::test]
    async fn only_the_standard_handles_are_inherited() {
        let dir = std::env::temp_dir();
        let pid = std::process::id();

        // Control: the ordinary way of starting a process inherits the handle.
        let control = dir.join(format!("openshell-inherit-control-{pid}.tmp"));
        let handle = open_exclusive_inheritable(&control);
        let mut ordinary = tokio::process::Command::new("cmd.exe")
            .args(["/c", "ping -n 30 127.0.0.1 >nul"])
            .kill_on_drop(true)
            .spawn()
            .expect("ordinary child");
        // SAFETY: the handle is valid and closed once.
        unsafe { CloseHandle(handle) }.unwrap();
        assert!(
            std::fs::remove_file(&control).is_err(),
            "control: the ordinary child should still hold the file open"
        );
        let _ = ordinary.kill().await;
        let _ = ordinary.wait().await;
        std::fs::remove_file(&control).expect("control file deletable once the child is gone");

        // Ours: the same handle is not inherited.
        let ours = dir.join(format!("openshell-inherit-ours-{pid}.tmp"));
        let job = GenerationJob::new().expect("job");
        let handle = open_exclusive_inheritable(&ours);
        let child = job
            .spawn(&quiet("cmd.exe", &["/c", "ping -n 30 127.0.0.1 >nul"]))
            .expect("spawn");
        // SAFETY: the handle is valid and closed once.
        unsafe { CloseHandle(handle) }.unwrap();
        let deleted = std::fs::remove_file(&ours);
        drop(child);
        deleted.expect("a sandbox process must not hold the host's other handles");
    }
}
