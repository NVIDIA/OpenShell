use super::{Command, Error};

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use openssh_mux_client::{shutdown_mux_master, Connection};
use tempfile::TempDir;

#[derive(Debug)]
pub(crate) struct Session {
    /// TempDir will automatically removes the temporary dir on drop
    tempdir: Option<TempDir>,
    ctl: Box<Path>,
}

impl Session {
    pub(crate) fn new(dir: TempDir) -> Self {
        let ctl = dir.path().join("master").into_boxed_path();

        Self {
            tempdir: Some(dir),
            ctl,
        }
    }

    pub(crate) fn resume(ctl: Box<Path>, _master_log: Option<Box<Path>>) -> Self {
        Self { tempdir: None, ctl }
    }

    pub(crate) async fn check(&self) -> Result<(), Error> {
        Connection::connect(&self.ctl)
            .await?
            .send_alive_check()
            .await?;

        Ok(())
    }

    pub(crate) fn ctl(&self) -> &Path {
        &self.ctl
    }

    pub(crate) fn raw_command<S: AsRef<OsStr>>(&self, program: S) -> Command {
        Command::new(self.ctl.clone(), program.as_ref().as_bytes().into(), false)
    }

    pub(crate) fn subsystem<S: AsRef<OsStr>>(&self, program: S) -> Command {
        Command::new(self.ctl.clone(), program.as_ref().as_bytes().into(), true)
    }

    pub(crate) async fn request_port_forward(
        &self,
        forward_type: crate::ForwardType,
        listen_socket: crate::Socket<'_>,
        connect_socket: crate::Socket<'_>,
    ) -> Result<(), Error> {
        Connection::connect(&self.ctl)
            .await?
            .request_port_forward(
                forward_type.into(),
                &listen_socket.into(),
                &connect_socket.into(),
            )
            .await?;

        Ok(())
    }

    pub(crate) async fn close_port_forward(
        &self,
        forward_type: crate::ForwardType,
        listen_socket: crate::Socket<'_>,
        connect_socket: crate::Socket<'_>,
    ) -> Result<(), Error> {
        Connection::connect(&self.ctl)
            .await?
            .close_port_forward(
                forward_type.into(),
                &listen_socket.into(),
                &connect_socket.into(),
            )
            .await?;

        Ok(())
    }

    async fn close_impl(&self) -> Result<(), Error> {
        Connection::connect(&self.ctl)
            .await?
            .request_stop_listening()
            .await?;

        Ok(())
    }

    pub(crate) async fn close(mut self) -> Result<Option<TempDir>, Error> {
        // Take self.tempdir so that drop would do nothing
        let tempdir = self.tempdir.take();

        self.close_impl().await?;

        Ok(tempdir)
    }

    pub(crate) fn detach(mut self) -> (Box<Path>, Option<Box<Path>>) {
        (
            self.ctl.clone(),
            self.tempdir.take().map(TempDir::into_path).map(|mut path| {
                path.push("log");
                path.into_boxed_path()
            }),
        )
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Keep tempdir alive until the shutdown request is sent
        let _tempdir = match self.tempdir.take() {
            Some(tempdir) => tempdir,
            // return since close must have already been called.
            None => return,
        };

        let _res = shutdown_mux_master(&self.ctl);
        #[cfg(feature = "tracing")]
        if let Err(err) = _res {
            tracing::error!("Closing ssh session failed: {}", err);
        }
    }
}
