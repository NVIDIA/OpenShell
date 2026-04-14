#![cfg_attr(docsrs, feature(doc_cfg))]

//! Provides a handle to the terminal of the current process that is both readable and writable.
//!
//! ## Example: Read and Write
//!```no_run
//! use terminal_trx::terminal;
//! use std::io::{BufReader, BufRead as _, Write as _};
//!
//! let mut terminal = terminal().unwrap();
//!
//! write!(terminal, "hello world").unwrap();
//!
//! let mut reader = BufReader::new(&mut terminal);
//! let mut line = String::new();
//! reader.read_line(&mut line).unwrap();
//! ```
//!
//! ## Example: Enable Raw Mode
//! ```no_run
//! use terminal_trx::terminal;
//!
//! let mut tty = terminal().unwrap();
//! let mut lock = tty.lock();
//! let mut raw_mode = lock.enable_raw_mode().unwrap();
//!
//! // You can now perform read and write operations using `raw_mode`.
//! ```

use cfg_if::cfg_if;
use std::io;
use std::marker::PhantomData;
use std::sync::{Mutex, MutexGuard};

cfg_if! {
    if #[cfg(all(unix, not(terminal_trx_test_unsupported)))] {
        mod unix;
        use unix as imp;
    } else if #[cfg(all(windows, not(terminal_trx_test_unsupported)))] {
        mod windows;
        use windows as imp;
    } else {
        mod unsupported;
        use unsupported as imp;
    }
}

#[doc = include_str!("../readme.md")]
#[cfg(doctest)]
pub mod readme_doctests {}

static TERMINAL_LOCK: Mutex<()> = Mutex::new(());

/// Creates a readable and writable handle to the terminal (or TTY) if available.
///
/// Use [`Terminal::lock`] if you want to avoid locking before each read / write call.
///
/// ## Unix
/// On Unix, the terminal is retrieved by successively testing
/// * the standard error,
/// * standard input,
/// * standard output,
/// * and finally `/dev/tty`.
///
/// ## Windows
/// On Windows, the reading half is retrieved by first testing the standard input, falling back to `CONIN$`. \
/// The writing half is retrieved by successfully testing
/// * the standard error,
/// * standard output,
/// * and finally `CONOUT$`.
pub fn terminal() -> io::Result<Terminal> {
    imp::terminal().map(Terminal)
}

macro_rules! impl_transceive {
    ($($extra_supertraits:tt)*) => {
        /// A trait for objects that are both [`io::Read`] and [`io::Write`].
        pub trait Transceive: io::Read + io::Write $($extra_supertraits)* + sealed::Sealed {}
    };
}

cfg_if! {
    if #[cfg(terminal_trx_test_unsupported)] {
        impl_transceive! { }
    } else if #[cfg(unix)] {
        impl_transceive! { + std::os::fd::AsFd + std::os::fd::AsRawFd }
    } else if #[cfg(windows)] {
        impl_transceive! { + ConsoleHandles }
    } else {
        impl_transceive! { }
    }
}

/// A trait to borrow the console handles from the underlying console.
#[cfg(all(windows, not(terminal_trx_test_unsupported)))]
#[cfg_attr(docsrs, doc(cfg(windows)))]
pub trait ConsoleHandles {
    /// Returns a handle to the consoles's input buffer `CONIN$`.
    fn input_buffer_handle(&self) -> std::os::windows::io::BorrowedHandle<'_>;

    /// Returns a handle to the consoles's screen buffer `CONOUT$`.
    fn screen_buffer_handle(&self) -> std::os::windows::io::BorrowedHandle<'_>;
}

mod sealed {
    pub trait Sealed {}
}

/// A readable and writable handle to the terminal (or TTY), created using [`terminal()`].
/// You can read and write data using the [`io::Read`] and [`io::Write`] implementations respectively.
///
/// Use [`Terminal::lock`] if you want to avoid locking before each read / write call.
#[derive(Debug)]
pub struct Terminal(imp::Terminal);

#[cfg(test)]
static_assertions::assert_impl_all!(Terminal: Send, Sync, std::panic::UnwindSafe, std::panic::RefUnwindSafe);

impl sealed::Sealed for Terminal {}
impl Transceive for Terminal {}

impl io::Read for Terminal {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.lock().read(buf)
    }
}

impl io::Write for Terminal {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.lock().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.lock().flush()
    }
}

impl Terminal {
    /// Locks access to this terminal, returing a guard that is readable and writable.
    ///
    /// Until the returned [`TerminalLock`] is dropped, all standard I/O streams
    /// that refer to the same terminal will be locked.
    pub fn lock(&mut self) -> TerminalLock<'_> {
        let mutex_guard = TERMINAL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let stdio_locks = self.0.lock_stdio();
        TerminalLock {
            inner: &mut self.0,
            _stdio_locks: stdio_locks,
            _mutex_guard: mutex_guard,
            _phantom_data: PhantomData,
        }
    }

    /// Tests if at least one of the standard I/O stream (stdin, stdout, stderr) is connected to this terminal.
    pub fn has_connected_stdio_stream(&self) -> bool {
        self.0.has_connected_stdio_stream()
    }
}

/// Guard for exclusive read- and write access to the terminal.
/// Can be created using [`Terminal::lock`].
#[derive(Debug)]
pub struct TerminalLock<'a> {
    inner: &'a mut imp::Terminal,
    _mutex_guard: MutexGuard<'static, ()>,
    _stdio_locks: StdioLocks,
    _phantom_data: PhantomData<*mut ()>,
}

#[cfg(test)]
static_assertions::assert_not_impl_any!(TerminalLock<'_>: Send, Sync);

impl TerminalLock<'_> {
    /// Enables raw mode on this terminal for the lifetime of the returned guard.
    ///
    /// Raw mode has two effects:
    /// * Input typed into the terminal is not visible.
    /// * Input is can be read immediately (usually input is only available after a newline character).
    /// * (Windows) Ensures that VT sequences are processed in both input and output.
    ///
    /// ### Windows
    /// This function returns an [`Err`] with [`ErrorKind::Unsupported`](`io::ErrorKind::Unsupported`) if the standard input is
    /// connected to a MSYS/Cygwin terminal.
    pub fn enable_raw_mode(&mut self) -> io::Result<RawModeGuard<'_>> {
        self.inner.enable_raw_mode().map(RawModeGuard)
    }
}

impl sealed::Sealed for TerminalLock<'_> {}
impl Transceive for TerminalLock<'_> {}

impl io::Read for TerminalLock<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl io::Write for TerminalLock<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[derive(Debug)]
struct StdioLocks {
    #[allow(dead_code)]
    stdin_lock: Option<io::StdinLock<'static>>,
    #[allow(dead_code)]
    stdout_lock: Option<io::StdoutLock<'static>>,
    #[allow(dead_code)]
    stderr_lock: Option<io::StderrLock<'static>>,
}

/// Guard for raw mode on the terminal, disables raw mode on drop.
/// Can be crated using [`TerminalLock::enable_raw_mode`].
#[derive(Debug)]
pub struct RawModeGuard<'a>(imp::RawModeGuard<'a>);

impl sealed::Sealed for RawModeGuard<'_> {}
impl Transceive for RawModeGuard<'_> {}

impl io::Read for RawModeGuard<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl io::Write for RawModeGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
