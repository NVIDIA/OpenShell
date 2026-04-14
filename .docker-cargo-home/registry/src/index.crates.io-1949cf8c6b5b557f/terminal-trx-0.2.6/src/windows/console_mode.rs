use super::to_io_result;
use std::io;
use std::os::windows::io::{AsRawHandle as _, BorrowedHandle};
use windows_sys::Win32::System::Console::{
    GetConsoleMode, SetConsoleMode, CONSOLE_MODE, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
    ENABLE_PROCESSED_OUTPUT, ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
};

pub(crate) fn get_console_mode(handle: BorrowedHandle) -> io::Result<CONSOLE_MODE> {
    let mut mode = Default::default();
    // SAFETY: Both handle and pointer are valid.
    to_io_result(unsafe { GetConsoleMode(handle.as_raw_handle(), &mut mode) })?;
    Ok(mode)
}

pub(crate) fn set_console_mode(handle: BorrowedHandle, mode: CONSOLE_MODE) -> io::Result<()> {
    // SAFETY: Handle is valid (borrowed).
    to_io_result(unsafe { SetConsoleMode(handle.as_raw_handle(), mode) })
}

pub(crate) mod input {
    use super::*;

    // We disable two flags:
    // `ENABLE_ECHO_INPUT`
    //     To disable input characters from being echoed.
    // `ENABLE_LINE_INPUT`
    //     We want input to be available immediately and not wait for a line terminator
    const FLAGS_DISABLED_IN_RAW_MODE: CONSOLE_MODE = ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT;

    // We enable one flag:
    // `ENABLE_VIRTUAL_TERMINAL_INPUT`
    //     To ensure that we get back a response. See: https://github.com/microsoft/terminal/pull/17729#issuecomment-2295339876
    const FLAGS_ENABLED_IN_RAW_MODE: CONSOLE_MODE = ENABLE_VIRTUAL_TERMINAL_INPUT;

    pub(crate) fn enable_raw_mode(mode: CONSOLE_MODE) -> CONSOLE_MODE {
        mode & !(FLAGS_DISABLED_IN_RAW_MODE) | FLAGS_ENABLED_IN_RAW_MODE
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn enabled_and_disabled_flags_do_not_overlap() {
            assert_eq!(0, FLAGS_DISABLED_IN_RAW_MODE & FLAGS_ENABLED_IN_RAW_MODE);
        }
    }
}

pub(crate) mod output {
    use super::*;

    // Let's ensure that VT sequences are processed.
    const FLAGS_ENABLED_IN_RAW_MODE: CONSOLE_MODE =
        ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING;

    pub(crate) fn enable_raw_mode(mode: CONSOLE_MODE) -> CONSOLE_MODE {
        mode | FLAGS_ENABLED_IN_RAW_MODE
    }
}
