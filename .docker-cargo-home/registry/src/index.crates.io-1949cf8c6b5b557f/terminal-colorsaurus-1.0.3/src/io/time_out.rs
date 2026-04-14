use std::error::Error;
use std::{fmt, io};

pub(crate) fn read_timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, PollReadTimedOutError)
}

#[derive(Debug)]
struct PollReadTimedOutError;

impl fmt::Display for PollReadTimedOutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "poll_read timed out")
    }
}

impl Error for PollReadTimedOutError {}
