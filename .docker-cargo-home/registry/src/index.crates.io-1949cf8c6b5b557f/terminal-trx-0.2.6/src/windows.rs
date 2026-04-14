use self::console_mode::{get_console_mode, set_console_mode};
use crate::{ConsoleHandles, StdioLocks};
use core::fmt;
use msys::msys_tty_on;
use std::error;
use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal};
use std::mem::ManuallyDrop;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, RawHandle};
use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::CompareObjectHandles;
use windows_sys::Win32::System::Console::CONSOLE_MODE;

mod console_mode;
mod msys;

pub(crate) fn terminal() -> io::Result<Terminal> {
    let conin = conin()?;
    let conout = conout()?;
    let conin_same_as_stdin = compare_object_handles(conin.as_handle(), io::stdin());
    let conout_same_as_stdout = compare_object_handles(conout.as_handle(), io::stdout());
    let conout_same_as_stderr = compare_object_handles(conout.as_handle(), io::stderr());
    Ok(Terminal {
        conin,
        conout,
        conin_same_as_stdin,
        conout_same_as_stdout,
        conout_same_as_stderr,
    })
}

fn conin() -> io::Result<ConsoleBuffer> {
    ConsoleBuffer::try_borrow(io::stdin())
        .map(Ok)
        .unwrap_or_else(|| {
            OpenOptions::new()
                .read(true)
                // The docs for `SetConsoleMode` claim that only GENERIC_READ is needed,
                // but I get an access denied error without also enabling write access.
                .write(true)
                .open("CONIN$")
                .map(ConsoleBuffer::Owned)
        })
}

fn conout() -> io::Result<ConsoleBuffer> {
    ConsoleBuffer::try_borrow(io::stderr())
        .or_else(|| ConsoleBuffer::try_borrow(io::stdout()))
        .map(Ok)
        .unwrap_or_else(|| {
            OpenOptions::new()
                .write(true)
                .open("CONOUT$")
                .map(ConsoleBuffer::Owned)
        })
}

#[derive(Debug)]
pub(crate) struct Terminal {
    conin: ConsoleBuffer,
    conout: ConsoleBuffer,
    conin_same_as_stdin: bool,
    conout_same_as_stdout: bool,
    conout_same_as_stderr: bool,
}

#[derive(Debug)]
pub(crate) enum ConsoleBuffer {
    Owned(File),
    Borrowed(ManuallyDrop<File>),
}

impl ConsoleBuffer {
    // SAFETY: Only pass handles to global standard I/O that lives for the entire duration of the program.
    fn try_borrow(handle: impl AsHandle) -> Option<ConsoleBuffer> {
        let handle = handle.as_handle();
        handle.is_terminal().then(|| {
            // SAFETY: We pass a valid handle and we ensure that the
            // standard I/O handle is not closed by wrapping the file in `ManuallyDrop`.
            ConsoleBuffer::Borrowed(ManuallyDrop::new(unsafe {
                File::from_raw_handle(handle.as_raw_handle())
            }))
        })
    }
}

impl io::Write for Terminal {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.conout.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.conout.flush()
    }
}

impl AsHandle for ConsoleBuffer {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        match self {
            ConsoleBuffer::Owned(f) => f.as_handle(),
            ConsoleBuffer::Borrowed(f) => f.as_handle(),
        }
    }
}

impl AsRawHandle for ConsoleBuffer {
    fn as_raw_handle(&self) -> RawHandle {
        match self {
            ConsoleBuffer::Owned(f) => f.as_raw_handle(),
            ConsoleBuffer::Borrowed(f) => f.as_raw_handle(),
        }
    }
}

impl io::Write for ConsoleBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            ConsoleBuffer::Owned(f) => f.write(buf),
            ConsoleBuffer::Borrowed(f) => f.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            ConsoleBuffer::Owned(f) => f.flush(),
            ConsoleBuffer::Borrowed(f) => f.flush(),
        }
    }
}

impl io::Read for Terminal {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.conin.read(buf)
    }
}

impl io::Read for ConsoleBuffer {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ConsoleBuffer::Owned(f) => f.read(buf),
            ConsoleBuffer::Borrowed(f) => f.read(buf),
        }
    }
}

impl Terminal {
    pub(crate) fn lock_stdio(&mut self) -> StdioLocks {
        let stdin_lock = self.conin_same_as_stdin.then(|| io::stdin().lock());
        let stdout_lock = self.conout_same_as_stdout.then(|| io::stdout().lock());
        let stderr_lock = self.conout_same_as_stderr.then(|| io::stderr().lock());
        StdioLocks {
            stdin_lock,
            stdout_lock,
            stderr_lock,
        }
    }

    pub(crate) fn enable_raw_mode(&mut self) -> io::Result<RawModeGuard<'_>> {
        let conin = self.conin.as_handle();
        let conout = self.conout.as_handle();

        // `is_terminal` recognizes MSYS/Cygwin pipes as terminal,
        // but they are not a console, so we bail out.
        if msys_tty_on(conin) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                MsysUnsupportedError,
            ));
        }

        let old_input_mode =
            set_raw_mode_if_necessary(conin, console_mode::input::enable_raw_mode)?;
        let old_output_mode =
            set_raw_mode_if_necessary(conout, console_mode::output::enable_raw_mode)?;
        Ok(RawModeGuard {
            inner: self,
            old_input_mode,
            old_output_mode,
        })
    }

    pub(crate) fn has_connected_stdio_stream(&self) -> bool {
        self.conin_same_as_stdin || self.conout_same_as_stdout || self.conout_same_as_stderr
    }
}

fn set_raw_mode_if_necessary(
    handle: BorrowedHandle,
    enable: fn(CONSOLE_MODE) -> CONSOLE_MODE,
) -> io::Result<Option<CONSOLE_MODE>> {
    let mode = get_console_mode(handle)?;
    let new_mode = enable(mode);
    if mode == new_mode {
        Ok(None)
    } else {
        set_console_mode(handle, new_mode)?;
        Ok(Some(mode))
    }
}

#[derive(Debug)]
struct MsysUnsupportedError;

impl fmt::Display for MsysUnsupportedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "enabling raw mode on a MSYS/Cygwin terminal is not supported"
        )
    }
}

impl error::Error for MsysUnsupportedError {}

#[derive(Debug)]
pub(crate) struct RawModeGuard<'a> {
    inner: &'a mut Terminal,
    old_input_mode: Option<CONSOLE_MODE>,
    old_output_mode: Option<CONSOLE_MODE>,
}

impl Drop for RawModeGuard<'_> {
    fn drop(&mut self) {
        if let Some(old_mode) = self.old_input_mode {
            _ = set_console_mode(self.inner.conin.as_handle(), old_mode);
        }
        if let Some(old_mode) = self.old_output_mode {
            _ = set_console_mode(self.inner.conout.as_handle(), old_mode);
        }
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

fn to_io_result(result: BOOL) -> io::Result<()> {
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

impl ConsoleHandles for super::Terminal {
    fn input_buffer_handle(&self) -> std::os::windows::io::BorrowedHandle<'_> {
        self.0.conin.as_handle()
    }

    fn screen_buffer_handle(&self) -> std::os::windows::io::BorrowedHandle<'_> {
        self.0.conout.as_handle()
    }
}

impl ConsoleHandles for super::TerminalLock<'_> {
    fn input_buffer_handle(&self) -> std::os::windows::io::BorrowedHandle<'_> {
        self.inner.conin.as_handle()
    }

    fn screen_buffer_handle(&self) -> std::os::windows::io::BorrowedHandle<'_> {
        self.inner.conout.as_handle()
    }
}

impl ConsoleHandles for super::RawModeGuard<'_> {
    fn input_buffer_handle(&self) -> std::os::windows::io::BorrowedHandle<'_> {
        self.0.inner.conin.as_handle()
    }

    fn screen_buffer_handle(&self) -> std::os::windows::io::BorrowedHandle<'_> {
        self.0.inner.conout.as_handle()
    }
}

fn compare_object_handles(first: impl AsRawHandle, second: impl AsRawHandle) -> bool {
    use windows_sys::Win32::Foundation::HANDLE;
    let first = first.as_raw_handle() as HANDLE;
    let second = second.as_raw_handle() as HANDLE;
    // SAFETY: We pass two valid handles
    unsafe { CompareObjectHandles(first, second) == 1 }
}
