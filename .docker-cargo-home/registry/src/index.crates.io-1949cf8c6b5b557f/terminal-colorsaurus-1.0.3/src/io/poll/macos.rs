use super::super::read_timed_out;
use libc::{c_int, pselect, time_t, timespec, FD_ISSET, FD_SET};
use std::io;
use std::mem::zeroed;
use std::ptr::{null, null_mut};
use std::time::Duration;
use terminal_trx::Transceive;

// macOS does not support polling /dev/tty using kqueue, so we have to
// resort to pselect/select. See https://nathancraddock.com/blog/macos-dev-tty-polling/.
pub(crate) fn poll_read(terminal: &dyn Transceive, timeout: Duration) -> io::Result<()> {
    if timeout.is_zero() {
        return Err(read_timed_out());
    }

    let fd = terminal.as_raw_fd();
    let timespec = to_timespec(timeout);
    // SAFETY: A zeroed fd_set is valid (FD_ZERO zeroes an existing fd_set so this state must be fine).
    // Our file descriptor is valid since we get it from safe code.
    unsafe {
        let mut readfds = zeroed();
        FD_SET(fd, &mut readfds);
        // The nfds argument is not "number of file descriptors" but biggest file descriptor + 1.
        to_io_result(pselect(
            fd + 1,
            &mut readfds,
            null_mut(),
            null_mut(),
            &timespec,
            null(),
        ))?;
        if FD_ISSET(fd, &readfds) {
            Ok(())
        } else {
            Err(read_timed_out())
        }
    }
}

fn to_timespec(duration: Duration) -> timespec {
    timespec {
        tv_sec: duration.as_secs() as time_t,
        #[cfg(all(target_arch = "x86_64", target_pointer_width = "32"))]
        tv_nsec: duration.subsec_nanos() as i64,
        #[cfg(not(all(target_arch = "x86_64", target_pointer_width = "32")))]
        tv_nsec: duration.subsec_nanos() as libc::c_long,
    }
}

fn to_io_result(value: c_int) -> io::Result<c_int> {
    if value == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}
