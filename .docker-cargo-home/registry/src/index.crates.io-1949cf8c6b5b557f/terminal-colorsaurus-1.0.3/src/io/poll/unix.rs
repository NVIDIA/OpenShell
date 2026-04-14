use super::super::read_timed_out;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use std::io;
use std::time::Duration;
use terminal_trx::Transceive;

pub(crate) fn poll_read(terminal: &dyn Transceive, timeout: Duration) -> io::Result<()> {
    if timeout.is_zero() {
        return Err(read_timed_out());
    }

    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(1024);
    let token = Token(0);
    poll.registry().register(
        &mut SourceFd(&terminal.as_raw_fd()),
        token,
        Interest::READABLE,
    )?;
    poll.poll(&mut events, Some(timeout))?;
    for event in &events {
        if event.token() == token {
            return Ok(());
        }
    }
    Err(read_timed_out())
}
