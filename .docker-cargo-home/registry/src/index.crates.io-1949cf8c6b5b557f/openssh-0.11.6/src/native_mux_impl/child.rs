use super::Error;

use std::io;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

use openssh_mux_client::{EstablishedSession, SessionStatus};

#[derive(Debug)]
pub(crate) struct RemoteChild {
    established_session: EstablishedSession,
}

impl RemoteChild {
    pub(crate) fn new(established_session: EstablishedSession) -> Self {
        Self {
            established_session,
        }
    }

    pub(crate) async fn disconnect(self) -> io::Result<()> {
        // ssh multiplex protocol does not specify any message type
        // that can be used to kill the remote process or properly shutdown
        // the connection.
        //
        // So here we just let the drop handler does its job to release
        // underlying resources such as unix stream socket and heap memory allocated,
        // the remote process is not killed.
        Ok(())
    }

    pub(crate) async fn wait(self) -> Result<ExitStatus, Error> {
        let session_status = self
            .established_session
            .wait()
            .await
            .map_err(|(err, _established_session)| err)?;

        match session_status {
            SessionStatus::TtyAllocFail(_established_session) => {
                unreachable!("native_mux_impl never allocates a tty")
            }
            SessionStatus::Exited { exit_value } => {
                if let Some(val) = exit_value {
                    if val == 127 {
                        Err(Error::Remote(io::Error::new(
                            io::ErrorKind::NotFound,
                            "remote command not found",
                        )))
                    } else {
                        Ok(ExitStatusExt::from_raw((val as i32) << 8))
                    }
                } else {
                    Err(Error::RemoteProcessTerminated)
                }
            }
        }
    }
}
