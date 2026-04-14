use libc::{grantpt, posix_openpt, unlockpt, O_CLOEXEC, O_NOCTTY, O_RDWR};
use std::ffi::{c_int, CStr, CString, OsStr};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt;

pub(crate) fn pty_pair() -> io::Result<PtyPair> {
    let controlling = openpty()?;
    let user = File::open(OsStr::from_bytes(
        ptsname_r(controlling.as_fd())?.as_bytes(),
    ))?
    .into();
    Ok(PtyPair {
        _controlling: controlling,
        user,
    })
}

#[derive(Debug)]
pub(crate) struct PtyPair {
    pub(crate) _controlling: OwnedFd,
    pub(crate) user: OwnedFd,
}

fn openpty() -> io::Result<OwnedFd> {
    // O_RDWR:
    //   Open the device for both reading and writing.
    // O_NOCTTY:
    //   Do not make this device the controlling terminal for the process.
    // O_CLOEXEC:
    //   Enables the close-on-exec flag for the new file descriptor
    //   meaning that child processes won't inherit this file descriptor.
    // SAFETY: We check that the file descriptor is valid (not -1).
    let fd = to_io_result(unsafe { posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC) })?;
    // SAFETY: We just created the fd, so we know it's valid.
    to_io_result(unsafe { grantpt(fd) })?;
    // SAFETY: We just created the fd, so we know it's valid.
    to_io_result(unsafe { unlockpt(fd) })?;
    // SAFETY: posix_openpt creates a new fd for us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(not(target_os = "macos"))]
fn ptsname_r(fd: BorrowedFd) -> io::Result<CString> {
    let mut buf = Vec::with_capacity(64);

    loop {
        // SAFETY: We pass the capacity of our vec to ptsname_r.
        let code = unsafe { libc::ptsname_r(fd.as_raw_fd(), buf.as_mut_ptr(), buf.capacity()) };
        match code {
            // SAFETY: We own the pointer and we know that if ptsname_r is successful, it returns a null-terminated string.
            0 => return Ok(unsafe { CStr::from_ptr(buf.as_ptr()).to_owned() }),
            libc::ERANGE => buf.reserve(64),
            code => return Err(io::Error::from_raw_os_error(code)),
        }
    }
}

/// macOS does not have `ptsname_r` (the race free version), so we have to resort to `ioctl`.
#[cfg(target_os = "macos")]
fn ptsname_r(fd: BorrowedFd) -> io::Result<CString> {
    // This is based on
    // https://github.com/Mobivity/nix-ptsname_r-shim/blob/master/src/lib.rs
    // which in turn is based on
    // https://blog.tarq.io/ptsname-on-osx-with-rust/
    // and its derivative
    // https://github.com/philippkeller/rexpect/blob/a71dd02/src/process.rs#L67
    use libc::{c_ulong, ioctl, TIOCPTYGNAME};

    // the buffer size on OSX is 128, defined by sys/ttycom.h
    let buf: [i8; 128] = [0; 128];

    // SAFETY: Our buffer is big enough according to the docs.
    // Creating the CStr is also ok, since we know that we get back a null-terminated string.
    unsafe {
        match ioctl(fd.as_raw_fd(), TIOCPTYGNAME as c_ulong, &buf) {
            0 => {
                let res = CStr::from_ptr(buf.as_ptr()).to_owned();
                Ok(res)
            }
            _ => Err(io::Error::last_os_error()),
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
