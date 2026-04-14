use std::{
    fs, io,
    os::unix::{
        io::{IntoRawFd, RawFd},
        prelude::AsRawFd,
    },
};

use libc::size_t;

/// A file descriptor wrapper.
///
/// It allows to retrieve raw file descriptor, write to the file descriptor and
/// mainly it closes the file descriptor once dropped.
#[derive(Debug)]
pub struct FileDesc {
    fd: RawFd,
    close_on_drop: bool,
}

impl FileDesc {
    /// Constructs a new `FileDesc` with the given `RawFd`.
    ///
    /// # Arguments
    ///
    /// * `fd` - raw file descriptor
    /// * `close_on_drop` - specify if the raw file descriptor should be closed once the `FileDesc` is dropped
    pub fn new(fd: RawFd, close_on_drop: bool) -> FileDesc {
        FileDesc { fd, close_on_drop }
    }

    pub fn read(&self, buffer: &mut [u8], size: usize) -> io::Result<usize> {
        let result = unsafe {
            libc::read(
                self.fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                size as size_t,
            )
        };

        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
    }

    /// Returns the underlying file descriptor.
    pub fn raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for FileDesc {
    fn drop(&mut self) {
        if self.close_on_drop {
            // Note that errors are ignored when closing a file descriptor. The
            // reason for this is that if an error occurs we don't actually know if
            // the file descriptor was closed or not, and if we retried (for
            // something like EINTR), we might close another valid file descriptor
            // opened after we closed ours.
            let _ = unsafe { libc::close(self.fd) };
        }
    }
}

impl AsRawFd for FileDesc {
    fn as_raw_fd(&self) -> RawFd {
        self.raw_fd()
    }
}

/// Creates a file descriptor pointing to the standard input or `/dev/tty`.
pub fn tty_fd() -> io::Result<FileDesc> {
    let (fd, close_on_drop) = if unsafe { libc::isatty(libc::STDIN_FILENO) == 1 } {
        (libc::STDIN_FILENO, false)
    } else {
        (
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tty")?
                .into_raw_fd(),
            true,
        )
    };

    Ok(FileDesc::new(fd, close_on_drop))
}
