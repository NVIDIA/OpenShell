use super::{ChildStderr, ChildStdin, ChildStdout, Error};

use std::io;
use std::process::{ExitStatus, Output};

use tokio::io::AsyncReadExt;
use tokio::try_join;

#[derive(Debug)]
pub(crate) enum RemoteChildImp {
    #[cfg(feature = "process-mux")]
    ProcessImpl(super::process_impl::RemoteChild),

    #[cfg(feature = "native-mux")]
    NativeMuxImpl(super::native_mux_impl::RemoteChild),
}
#[cfg(feature = "process-mux")]
impl From<super::process_impl::RemoteChild> for RemoteChildImp {
    fn from(imp: super::process_impl::RemoteChild) -> Self {
        RemoteChildImp::ProcessImpl(imp)
    }
}

#[cfg(feature = "native-mux")]
impl From<super::native_mux_impl::RemoteChild> for RemoteChildImp {
    fn from(imp: super::native_mux_impl::RemoteChild) -> Self {
        RemoteChildImp::NativeMuxImpl(imp)
    }
}

macro_rules! delegate {
    ($impl:expr, $var:ident, $then:block) => {{
        match $impl {
            #[cfg(feature = "process-mux")]
            RemoteChildImp::ProcessImpl($var) => $then,

            #[cfg(feature = "native-mux")]
            RemoteChildImp::NativeMuxImpl($var) => $then,
        }
    }};
}

/// Representation of a running or exited remote child process.
///
/// This structure is used to represent and manage remote child
/// processes. A remote child process is created via the
/// [`OwningCommand`](crate::OwningCommand) struct through
/// [`Session::command`](crate::Session::command) or one of its
/// variants, which configures the spawning process and can itself be
/// constructed using a builder-style interface.
///
/// Calling [`wait`](Child::wait) (or other functions that wrap around it) will make the
/// parent process wait until the child has actually exited before continuing.
///
/// Unlike [`std::process::Child`], `Child` *does* implement [`Drop`], and will terminate the
/// local `ssh` process corresponding to the remote process when it goes out of scope. Note that
/// this does _not_ terminate the remote process. If you want to do that, you will need to kill it
/// yourself by executing a remote command like `pkill` to kill it on the remote side.
///
/// As a result, `Child` cannot expose `stdin`, `stdout`, and `stderr` as fields for
/// split-borrows like [`std::process::Child`] does. Instead, it exposes
/// [`stdin`](Child::stdin), [`stdout`](Child::stdout),
/// and [`stderr`](Child::stderr) as methods. Callers can call `.take()` to get the same
/// effect as a split borrow and use multiple streams concurrently. Note that for the streams to be
/// available,`Stdio::piped()` should be passed to the corresponding method on
/// [`OwningCommand`](crate::OwningCommand).
///
/// NOTE that once `Child` is dropped, any data written to `stdin` will not be sent to the
/// remote process and `stdout` and `stderr` will yield EOF immediately.
///
/// ```rust,no_run
/// # async fn foo() {
/// # let child: openssh::RemoteChild<'static> = unimplemented!();
/// let stdin = child.stdin().take().unwrap();
/// let stdout = child.stdout().take().unwrap();
/// tokio::io::copy(&mut stdout, &mut stdin).await;
/// # }
/// ```
#[derive(Debug)]
pub struct Child<S> {
    session: S,
    imp: RemoteChildImp,

    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
}

impl<S> Child<S> {
    pub(crate) fn new(
        session: S,
        (imp, stdin, stdout, stderr): (
            RemoteChildImp,
            Option<ChildStdin>,
            Option<ChildStdout>,
            Option<ChildStderr>,
        ),
    ) -> Self {
        Self {
            session,
            stdin,
            stdout,
            stderr,
            imp,
        }
    }

    /// Disconnect from this given remote child process.
    ///
    /// Note that disconnecting does _not_ kill the remote process, it merely kills the local
    /// handle to that remote process.
    pub async fn disconnect(self) -> io::Result<()> {
        delegate!(self.imp, imp, { imp.disconnect().await })
    }

    /// Waits for the remote child to exit completely, returning the status that it exited with.
    ///
    /// This function will continue to have the same return value after it has been called at least
    /// once.
    ///
    /// The stdin handle to the child process, if any, will be closed before waiting. This helps
    /// avoid deadlock: it ensures that the child does not block waiting for input from the parent,
    /// while the parent waits for the child to exit.
    pub async fn wait(mut self) -> Result<ExitStatus, Error> {
        // Close stdin so that if the remote process is reading stdin,
        // it would return EOF and the remote process can exit.
        self.stdin().take();

        delegate!(self.imp, imp, { imp.wait().await })
    }

    /// Simultaneously waits for the remote child to exit and collect all remaining output on the
    /// stdout/stderr handles, returning an `Output` instance.
    ///
    /// The stdin handle to the child process, if any, will be closed before waiting. This helps
    /// avoid deadlock: it ensures that the child does not block waiting for input from the parent,
    /// while the parent waits for the child to exit.
    ///
    /// By default, stdin, stdout and stderr are inherited from the parent. In order to capture the
    /// output into this `Result<Output>` it is necessary to create new pipes between parent and
    /// child. Use `stdout(Stdio::piped())` or `stderr(Stdio::piped())`, respectively.
    pub async fn wait_with_output(mut self) -> Result<Output, Error> {
        self.stdin().take();

        let child_stdout = self.stdout.take();
        let stdout_read = async move {
            let mut stdout = Vec::new();

            if let Some(mut child_stdout) = child_stdout {
                child_stdout
                    .read_to_end(&mut stdout)
                    .await
                    .map_err(Error::ChildIo)?;
            }

            Ok::<_, Error>(stdout)
        };

        let child_stderr = self.stderr.take();
        let stderr_read = async move {
            let mut stderr = Vec::new();

            if let Some(mut child_stderr) = child_stderr {
                child_stderr
                    .read_to_end(&mut stderr)
                    .await
                    .map_err(Error::ChildIo)?;
            }

            Ok::<_, Error>(stderr)
        };

        // Execute them concurrently to avoid the pipe buffer being filled up
        // and cause the remote process to block forever.
        let (stdout, stderr) = try_join!(stdout_read, stderr_read)?;
        Ok(Output {
            // The self.wait() future terminates the stdout and stderr futures
            // when it resolves, even if there may still be more data arriving
            // from the server.
            //
            // Therefore, we wait for them first, and only once they're complete
            // do we wait for the process to have terminated.
            status: self.wait().await?,
            stdout,
            stderr,
        })
    }

    /// Access the handle for reading from the remote child's standard input (stdin), if requested.
    pub fn stdin(&mut self) -> &mut Option<ChildStdin> {
        &mut self.stdin
    }

    /// Access the handle for reading from the remote child's standard output (stdout), if
    /// requested.
    pub fn stdout(&mut self) -> &mut Option<ChildStdout> {
        &mut self.stdout
    }

    /// Access the handle for reading from the remote child's standard error (stderr), if requested.
    pub fn stderr(&mut self) -> &mut Option<ChildStderr> {
        &mut self.stderr
    }
}

impl<S: Clone> Child<S> {
    /// Access the SSH session that this remote process was spawned from.
    pub fn session(&self) -> S {
        self.session.clone()
    }
}
