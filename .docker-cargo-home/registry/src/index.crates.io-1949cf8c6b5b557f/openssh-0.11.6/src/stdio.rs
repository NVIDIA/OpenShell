use super::Error;

#[cfg(feature = "native-mux")]
use super::native_mux_impl;

use std::fs::File;
use std::io;
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::process;
use std::task::{Context, Poll};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::unix::pipe::{Receiver as PipeReader, Sender as PipeWriter},
};

#[derive(Debug)]
pub(crate) enum StdioImpl {
    /// Read/Write to /dev/null
    Null,
    /// Read/Write to a newly created pipe
    Pipe,
    /// Read/Write to custom fd
    Fd(OwnedFd),
    /// Inherit stdin/stdout/stderr
    Inherit,
}

/// Describes what to do with a standard I/O stream for a remote child process
/// when passed to the stdin, stdout, and stderr methods of Command.
#[derive(Debug)]
pub struct Stdio(pub(crate) StdioImpl);
impl Stdio {
    /// A new pipe should be arranged to connect the parent and remote child processes.
    pub const fn piped() -> Self {
        Self(StdioImpl::Pipe)
    }

    /// This stream will be ignored.
    /// This is the equivalent of attaching the stream to /dev/null.
    pub const fn null() -> Self {
        Self(StdioImpl::Null)
    }

    /// The child inherits from the corresponding parent descriptor.
    ///
    /// NOTE that the stdio fd must be in blocking mode, otherwise
    /// ssh might not flush all output since it considers
    /// (`EAGAIN`/`EWOULDBLOCK`) as an error
    pub const fn inherit() -> Self {
        Self(StdioImpl::Inherit)
    }

    /// `Stdio::from_raw_fd_owned` takes ownership of the fd passed in
    /// and closes the fd on drop.
    ///
    /// NOTE that the fd will be put into blocking mode, then it will be
    /// closed when `Stdio` is dropped.
    ///
    /// # Safety
    ///
    /// * `fd` - must be a valid fd and must give its ownership to `Stdio`.
    pub unsafe fn from_raw_fd_owned(fd: RawFd) -> Self {
        Self(StdioImpl::Fd(OwnedFd::from_raw_fd(fd)))
    }
}

impl From<Stdio> for process::Stdio {
    fn from(stdio: Stdio) -> Self {
        match stdio.0 {
            StdioImpl::Null => process::Stdio::null(),
            StdioImpl::Pipe => process::Stdio::piped(),
            StdioImpl::Inherit => process::Stdio::inherit(),
            StdioImpl::Fd(fd) => process::Stdio::from(fd),
        }
    }
}

impl From<OwnedFd> for Stdio {
    fn from(fd: OwnedFd) -> Self {
        Self(StdioImpl::Fd(fd))
    }
}

macro_rules! impl_from_for_stdio {
    ($type:ty) => {
        impl From<$type> for Stdio {
            fn from(arg: $type) -> Self {
                Self(StdioImpl::Fd(arg.into()))
            }
        }
    };
}

macro_rules! impl_try_from_for_stdio {
    ($type:ty) => {
        impl TryFrom<$type> for Stdio {
            type Error = Error;
            fn try_from(arg: $type) -> Result<Self, Self::Error> {
                Ok(Self(StdioImpl::Fd(
                    arg.into_owned_fd().map_err(Error::ChildIo)?,
                )))
            }
        }
    };
}

impl_from_for_stdio!(process::ChildStdin);
impl_from_for_stdio!(process::ChildStdout);
impl_from_for_stdio!(process::ChildStderr);

impl_try_from_for_stdio!(ChildStdin);
impl_try_from_for_stdio!(ChildStdout);
impl_try_from_for_stdio!(ChildStderr);

impl_from_for_stdio!(File);

macro_rules! impl_try_from_tokio_process_child_for_stdio {
    ($type:ident) => {
        impl TryFrom<tokio::process::$type> for Stdio {
            type Error = Error;

            fn try_from(arg: tokio::process::$type) -> Result<Self, Self::Error> {
                arg.into_owned_fd().map_err(Error::ChildIo).map(Into::into)
            }
        }
    };
}

impl_try_from_tokio_process_child_for_stdio!(ChildStdin);
impl_try_from_tokio_process_child_for_stdio!(ChildStdout);
impl_try_from_tokio_process_child_for_stdio!(ChildStderr);

/// Input for the remote child.
#[derive(Debug)]
pub struct ChildStdin(PipeWriter);

/// Stdout for the remote child.
#[derive(Debug)]
pub struct ChildStdout(PipeReader);

/// Stderr for the remote child.
#[derive(Debug)]
pub struct ChildStderr(PipeReader);

pub(crate) trait TryFromChildIo<T>: Sized {
    type Error;

    fn try_from(arg: T) -> Result<Self, Self::Error>;
}

macro_rules! impl_from_impl_child_io {
    (process, $type:ident, $inner:ty) => {
        impl TryFromChildIo<tokio::process::$type> for $type {
            type Error = Error;

            fn try_from(arg: tokio::process::$type) -> Result<Self, Self::Error> {
                let fd = arg.into_owned_fd().map_err(Error::ChildIo)?;

                <$inner>::from_owned_fd(fd)
                    .map(Self)
                    .map_err(Error::ChildIo)
            }
        }
    };

    (native_mux, $type:ident) => {
        #[cfg(feature = "native-mux")]
        impl TryFromChildIo<native_mux_impl::$type> for $type {
            type Error = Error;

            fn try_from(arg: native_mux_impl::$type) -> Result<Self, Self::Error> {
                Ok(Self(arg))
            }
        }
    };
}

impl_from_impl_child_io!(process, ChildStdin, PipeWriter);
impl_from_impl_child_io!(process, ChildStdout, PipeReader);
impl_from_impl_child_io!(process, ChildStderr, PipeReader);

impl_from_impl_child_io!(native_mux, ChildStdin);
impl_from_impl_child_io!(native_mux, ChildStdout);
impl_from_impl_child_io!(native_mux, ChildStderr);

macro_rules! impl_child_stdio {
    (AsRawFd, $type:ty) => {
        impl AsRawFd for $type {
            fn as_raw_fd(&self) -> RawFd {
                self.0.as_raw_fd()
            }
        }
    };

    (AsFd, $type:ty) => {
        impl AsFd for $type {
            fn as_fd(&self) -> BorrowedFd<'_> {
                self.0.as_fd()
            }
        }
    };

    (into_owned_fd, $type:ty) => {
        impl $type {
            /// Convert into an owned fd, it'd be deregisted from tokio and in blocking mode.
            pub fn into_owned_fd(self) -> io::Result<OwnedFd> {
                self.0.into_blocking_fd()
            }
        }
    };

    (AsyncRead, $type:ty) => {
        impl_child_stdio!(AsRawFd, $type);
        impl_child_stdio!(AsFd, $type);
        impl_child_stdio!(into_owned_fd, $type);

        impl AsyncRead for $type {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.0).poll_read(cx, buf)
            }
        }
    };

    (AsyncWrite, $type: ty) => {
        impl_child_stdio!(AsRawFd, $type);
        impl_child_stdio!(AsFd, $type);
        impl_child_stdio!(into_owned_fd, $type);

        impl AsyncWrite for $type {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Pin::new(&mut self.0).poll_write(cx, buf)
            }

            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.0).poll_flush(cx)
            }

            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.0).poll_shutdown(cx)
            }

            fn poll_write_vectored(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                bufs: &[io::IoSlice<'_>],
            ) -> Poll<io::Result<usize>> {
                Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
            }

            fn is_write_vectored(&self) -> bool {
                self.0.is_write_vectored()
            }
        }
    };
}

impl_child_stdio!(AsyncWrite, ChildStdin);
impl_child_stdio!(AsyncRead, ChildStdout);
impl_child_stdio!(AsyncRead, ChildStderr);
