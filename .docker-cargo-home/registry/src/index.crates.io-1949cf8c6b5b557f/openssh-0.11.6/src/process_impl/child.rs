use super::Error;

use std::io;
use std::process::ExitStatus;

use tokio::process;

// Disconnects the ssh session at drop, but does not kill the remote process.
#[derive(Debug)]
pub(crate) struct RemoteChild {
    channel: process::Child,
}

impl RemoteChild {
    /// * `channel` - Must be created with `process::Command::kill_on_drop(true)`.
    pub(crate) fn new(channel: process::Child) -> Self {
        Self { channel }
    }

    pub(crate) async fn disconnect(mut self) -> io::Result<()> {
        // this disconnects, but does not kill the remote process
        self.channel.kill().await?;

        Ok(())
    }

    pub(crate) async fn wait(mut self) -> Result<ExitStatus, Error> {
        match self.channel.wait().await {
            Err(e) => Err(Error::Remote(e)),
            Ok(w) => match w.code() {
                Some(255) => Err(Error::RemoteProcessTerminated),
                Some(127) => Err(Error::Remote(io::Error::new(
                    io::ErrorKind::NotFound,
                    "remote command not found",
                ))),
                _ => Ok(w),
            },
        }
    }
}
