use crate::StdioLocks;
use libc::{c_int, fcntl, termios, F_GETFL, O_RDWR};
use std::ffi::{CStr, CString, OsStr};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, stderr, stdin, stdout, IsTerminal};
use std::mem::{self, ManuallyDrop};
use std::ops::{Deref, DerefMut};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd as _};
use std::os::unix::ffi::OsStrExt;

mod attr;
#[cfg(test)]
mod pty_utils;
#[cfg(test)]
mod tests;

pub(crate) fn terminal() -> io::Result<Terminal> {
    None.or_else(|| reuse_tty_from_stdio(stderr).transpose())
        .or_else(|| reuse_tty_from_stdio(stdout).transpose())
        .or_else(|| reuse_tty_from_stdio(stdin).transpose())
        .map(|r| r.and_then(Terminal::from_stdio))
        .unwrap_or_else(|| Ok(Terminal::from_controlling(open_controlling_tty()?)))
}

fn reuse_tty_from_stdio<S: IsTerminal + AsFd>(
    stream: impl FnOnce() -> S,
) -> io::Result<Option<TerminalFile>> {
    let stream = stream();

    if stream.is_terminal() {
        // This branch here is a bit questionable to me:
        // I've seen a lot of code that re-uses the standard I/O fd if possible.
        // But I don't quite understand what the benefit of that is. Is it to have as little fds open as possible?
        // Is it a lot faster than opening the tty ourselves?
        if is_read_write(stream.as_fd())? {
            // SAFETY: We know that the file descriptor is valid.
            // However we break the assumption that the file descriptor is owned.
            // That's why the file is immediately wrapped in a ManuallyDrop to prevent
            // the standard I/O descriptor from being closed.
            let file = unsafe { File::from_raw_fd(stream.as_fd().as_raw_fd()) };
            Ok(Some(TerminalFile::Borrowed(ManuallyDrop::new(file))))
        } else {
            reopen_tty(stream.as_fd())
                .map(TerminalFile::Owned)
                .map(Some)
        }
    } else {
        Ok(None)
    }
}

fn open_controlling_tty() -> io::Result<TerminalFile> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map(TerminalFile::Owned)
}

fn is_read_write(fd: BorrowedFd) -> io::Result<bool> {
    // SAFETY: We know that the file descriptor is valid.
    let mode = to_io_result(unsafe { fcntl(fd.as_raw_fd(), F_GETFL) })?;
    Ok(mode & O_RDWR == O_RDWR)
}

fn reopen_tty(fd: BorrowedFd) -> io::Result<File> {
    let name = ttyname_r(fd)?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(OsStr::from_bytes(name.as_bytes()))
}

fn is_same_file(a: BorrowedFd, b: BorrowedFd) -> io::Result<bool> {
    Ok(a.as_raw_fd() == b.as_raw_fd() || {
        let stat_a = fstat(a)?;
        let stat_b = fstat(b)?;
        stat_a.st_dev == stat_b.st_dev && stat_a.st_ino == stat_b.st_ino
    })
}

fn fstat(fd: BorrowedFd) -> io::Result<libc::stat> {
    // SAFETY: If fstat is successful, then we get a valid stat structure.
    let mut stat = unsafe { mem::zeroed() };
    // SAFETY: We know that the file descriptor is valid.
    to_io_result(unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) })?;
    Ok(stat)
}

#[derive(Debug)]
pub(crate) struct Terminal {
    file: TerminalFile,
    same_as_stdin: bool,
    same_as_stdout: bool,
    same_as_stderr: bool,
}

impl Terminal {
    pub(crate) fn lock_stdio(&self) -> StdioLocks {
        StdioLocks {
            stdin_lock: self.same_as_stdin.then(|| stdin().lock()),
            stdout_lock: self.same_as_stdout.then(|| stdout().lock()),
            stderr_lock: self.same_as_stderr.then(|| stderr().lock()),
        }
    }

    pub(crate) fn enable_raw_mode(&mut self) -> io::Result<RawModeGuard<'_>> {
        let fd = self.file.as_fd();
        let old_termios = attr::get_terminal_attr(fd)?;

        if !attr::is_raw_mode_enabled(&old_termios) {
            let mut termios = old_termios;
            attr::enable_raw_mode(&mut termios);
            attr::set_terminal_attr(fd, &termios)?;
            Ok(RawModeGuard {
                inner: self,
                old_termios: Some(old_termios),
            })
        } else {
            Ok(RawModeGuard {
                inner: self,
                old_termios: None,
            })
        }
    }

    pub(crate) fn has_connected_stdio_stream(&self) -> bool {
        self.same_as_stdin || self.same_as_stdout || self.same_as_stderr
    }
}

impl Terminal {
    fn from_stdio(file: TerminalFile) -> io::Result<Self> {
        Ok(Terminal {
            same_as_stdin: is_same_file(file.as_fd(), stdin().as_fd())?,
            same_as_stdout: is_same_file(file.as_fd(), stdout().as_fd())?,
            same_as_stderr: is_same_file(file.as_fd(), stderr().as_fd())?,
            file,
        })
    }

    fn from_controlling(file: TerminalFile) -> Self {
        Terminal {
            file,
            same_as_stdin: false,
            same_as_stdout: false,
            same_as_stderr: false,
        }
    }
}

#[derive(Debug)]
enum TerminalFile {
    Owned(File),
    Borrowed(ManuallyDrop<File>),
}

impl io::Write for Terminal {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl io::Read for Terminal {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Deref for TerminalFile {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        match self {
            TerminalFile::Owned(f) => f,
            TerminalFile::Borrowed(f) => f,
        }
    }
}

impl DerefMut for TerminalFile {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            TerminalFile::Owned(f) => f,
            TerminalFile::Borrowed(f) => f,
        }
    }
}

impl AsFd for super::Terminal {
    fn as_fd(&self) -> std::os::unix::prelude::BorrowedFd<'_> {
        self.0.file.as_fd()
    }
}

impl AsFd for super::TerminalLock<'_> {
    fn as_fd(&self) -> std::os::unix::prelude::BorrowedFd<'_> {
        self.inner.file.as_fd()
    }
}

impl AsFd for super::RawModeGuard<'_> {
    fn as_fd(&self) -> std::os::unix::prelude::BorrowedFd<'_> {
        self.0.inner.file.as_fd()
    }
}

impl AsRawFd for super::Terminal {
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.0.file.as_raw_fd()
    }
}

impl AsRawFd for super::TerminalLock<'_> {
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.inner.file.as_raw_fd()
    }
}

impl AsRawFd for super::RawModeGuard<'_> {
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.0.inner.file.as_raw_fd()
    }
}

pub(crate) struct RawModeGuard<'a> {
    inner: &'a mut Terminal,
    old_termios: Option<termios>,
}

impl fmt::Debug for RawModeGuard<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawModeGuard")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl io::Write for RawModeGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl io::Read for RawModeGuard<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Drop for RawModeGuard<'_> {
    fn drop(&mut self) {
        if let Some(old_termios) = self.old_termios {
            _ = attr::set_terminal_attr(self.inner.file.as_fd(), &old_termios);
        }
    }
}

fn to_io_result(value: c_int) -> io::Result<c_int> {
    if value == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}

/// `ttyname_r` returns the path to the terminal device.
#[cfg(not(target_os = "macos"))]
fn ttyname_r(fd: BorrowedFd) -> io::Result<CString> {
    let mut buf = Vec::with_capacity(64);

    loop {
        // SAFETY: We pass the capacity of our vec to ttyname_r.
        let code = unsafe { libc::ttyname_r(fd.as_raw_fd(), buf.as_mut_ptr(), buf.capacity()) };
        match code {
            // SAFETY: We own the pointer and we know that if ttyname_r is successful, it returns a null-terminated string.
            0 => return Ok(unsafe { CStr::from_ptr(buf.as_ptr()) }.to_owned()),
            libc::ERANGE => buf.reserve(64),
            code => return Err(io::Error::from_raw_os_error(code)),
        }
    }
}

/// macOS does not have `ttyname_r` (the race free version), so we have to resort to `fcntl`.
#[cfg(target_os = "macos")]
fn ttyname_r(fd: BorrowedFd) -> io::Result<CString> {
    use libc::{F_GETPATH, PATH_MAX};

    // the buffer size must be >= MAXPATHLEN, see `man fcntl`
    let buf: [i8; PATH_MAX as usize] = [0; PATH_MAX as usize];

    unsafe {
        match fcntl(fd.as_raw_fd(), F_GETPATH as c_int, &buf) {
            0 => {
                let res = CStr::from_ptr(buf.as_ptr()).to_owned();
                Ok(res)
            }
            _ => Err(io::Error::last_os_error()),
        }
    }
}
