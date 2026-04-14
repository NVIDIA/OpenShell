use super::Error;
use super::RemoteChild;
use super::{ChildStderr, ChildStdin, ChildStdout};

use std::ffi::OsStr;
use std::process::Stdio;

use tokio::process;

#[derive(Debug)]
pub(crate) struct Command {
    builder: process::Command,
}

impl Command {
    pub(crate) fn new(mut builder: process::Command) -> Self {
        // Disconnects the ssh session at `RemoteChild::drop`, but does
        // not kill the remote process.
        builder.kill_on_drop(true);

        Self { builder }
    }
}

impl Command {
    pub(crate) fn raw_arg<S: AsRef<OsStr>>(&mut self, arg: S) {
        self.builder.arg(arg);
    }

    pub(crate) fn stdin<T: Into<Stdio>>(&mut self, cfg: T) {
        self.builder.stdin(cfg);
    }

    pub(crate) fn stdout<T: Into<Stdio>>(&mut self, cfg: T) {
        self.builder.stdout(cfg);
    }

    pub(crate) fn stderr<T: Into<Stdio>>(&mut self, cfg: T) {
        self.builder.stderr(cfg);
    }

    pub(crate) async fn spawn(
        &mut self,
    ) -> Result<
        (
            RemoteChild,
            Option<ChildStdin>,
            Option<ChildStdout>,
            Option<ChildStderr>,
        ),
        Error,
    > {
        #[cfg(feature = "tracing")]
        tracing::debug!(cmd = ?self.builder.as_std());

        let mut channel = self.builder.spawn().map_err(Error::Ssh)?;

        let child_stdin = channel.stdin.take();
        let child_stdout = channel.stdout.take();
        let child_stderr = channel.stderr.take();

        Ok((
            RemoteChild::new(channel),
            child_stdin,
            child_stdout,
            child_stderr,
        ))
    }
}
