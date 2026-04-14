use crate::StdioLocks;
use core::fmt;
use std::error;
use std::{io, marker::PhantomData};

pub(crate) fn terminal() -> io::Result<Terminal> {
    Err(io::Error::new(io::ErrorKind::Unsupported, UnsupportedError))
}

#[derive(Debug)]
struct UnsupportedError;

impl fmt::Display for UnsupportedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "this platform is not supported")
    }
}

impl error::Error for UnsupportedError {}

#[derive(Debug)]
pub(crate) struct Terminal {}

impl io::Write for Terminal {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        unreachable!()
    }

    fn flush(&mut self) -> io::Result<()> {
        unreachable!()
    }
}

impl io::Read for Terminal {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        unreachable!()
    }
}

impl Terminal {
    pub(crate) fn lock_stdio(&mut self) -> StdioLocks {
        unreachable!()
    }

    pub(crate) fn enable_raw_mode(&mut self) -> io::Result<RawModeGuard<'_>> {
        unreachable!()
    }

    pub(crate) fn has_connected_stdio_stream(&self) -> bool {
        unreachable!()
    }
}

#[derive(Debug)]
pub(crate) struct RawModeGuard<'a>(PhantomData<&'a ()>);

impl io::Write for RawModeGuard<'_> {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        unreachable!()
    }

    fn flush(&mut self) -> io::Result<()> {
        unreachable!()
    }
}

impl io::Read for RawModeGuard<'_> {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        unreachable!()
    }
}
