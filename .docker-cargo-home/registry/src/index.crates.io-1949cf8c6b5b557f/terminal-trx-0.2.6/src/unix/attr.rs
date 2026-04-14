use super::to_io_result;
use libc::{tcflag_t, termios};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::{io, mem};

pub(super) fn get_terminal_attr(fd: BorrowedFd) -> io::Result<termios> {
    // SAFETY: The termios structure is filled by tcgetattr if it returns successfully.
    unsafe {
        let mut termios = mem::zeroed();
        to_io_result(libc::tcgetattr(fd.as_raw_fd(), &mut termios))?;
        Ok(termios)
    }
}

pub(super) fn set_terminal_attr(fd: BorrowedFd, termios: &termios) -> io::Result<()> {
    // From the man page:
    // TCSADRAIN
    //     the change occurs after all output written to fd has been transmitted.
    //     This function should be used when changing parameters that affect output.
    // SAFETY: File descriptor is valid.
    to_io_result(unsafe { libc::tcsetattr(fd.as_raw_fd(), libc::TCSADRAIN, termios) }).and(Ok(()))
}

// We disable two flags:
// ECHO
//     to disable input characters from being echoed.
// ICANON
//     to disable canonical mode (we want input to be available immediately and not wait for a line terminator).
const FLAGS_DISABLED_IN_RAW_MODE: tcflag_t = libc::ICANON | libc::ECHO;

pub(super) fn enable_raw_mode(termios: &mut termios) {
    termios.c_lflag &= !FLAGS_DISABLED_IN_RAW_MODE;
}

pub(super) fn is_raw_mode_enabled(termios: &termios) -> bool {
    termios.c_lflag & FLAGS_DISABLED_IN_RAW_MODE == 0
}
