use hex::FromHex;
use hyper::{body::Body, rt::ReadBufCursor, Uri};
use hyper_util::{
    client::legacy::{
        connect::{Connected, Connection},
        Client,
    },
    rt::{TokioExecutor, TokioIo},
};
use pin_project_lite::pin_project;
use std::{
    future::Future,
    io,
    io::Error,
    path::{Path, PathBuf},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tower_service::Service;

pin_project! {
    /// Wrapper around [`tokio::net::UnixStream`].
    #[derive(Debug)]
    pub struct UnixStream {
        #[pin]
        unix_stream: tokio::net::UnixStream,
    }
}

impl UnixStream {
    async fn connect(path: impl AsRef<Path>) -> io::Result<Self> {
        let unix_stream = tokio::net::UnixStream::connect(path).await?;
        Ok(Self { unix_stream })
    }
}

impl AsyncWrite for UnixStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.project().unix_stream.poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        self.project().unix_stream.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        self.project().unix_stream.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, Error>> {
        self.project().unix_stream.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.unix_stream.is_write_vectored()
    }
}

impl hyper::rt::Write for UnixStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        self.project().unix_stream.poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Error>> {
        self.project().unix_stream.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Error>> {
        self.project().unix_stream.poll_shutdown(cx)
    }
}

impl AsyncRead for UnixStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().unix_stream.poll_read(cx, buf)
    }
}

impl hyper::rt::Read for UnixStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<Result<(), Error>> {
        let mut t = TokioIo::new(self.project().unix_stream);
        Pin::new(&mut t).poll_read(cx, buf)
    }
}

/// the `[UnixConnector]` can be used to construct a `[hyper::Client]` which can
/// speak to a unix domain socket.
///
/// # Example
/// ```
/// use http_body_util::Full;
/// use hyper::body::Bytes;
/// use hyper_util::{client::legacy::Client, rt::TokioExecutor};
/// use hyperlocal::UnixConnector;
///
/// let connector = UnixConnector;
/// let client: Client<UnixConnector, Full<Bytes>> =
///     Client::builder(TokioExecutor::new()).build(connector);
/// ```
///
/// # Note
/// If you don't need access to the low-level `[hyper::Client]` builder
/// interface, consider using the `[UnixClientExt]` trait instead.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnixConnector;

impl Unpin for UnixConnector {}

impl Service<Uri> for UnixConnector {
    type Response = UnixStream;
    type Error = io::Error;
    #[allow(clippy::type_complexity)]
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn call(
        &mut self,
        req: Uri,
    ) -> Self::Future {
        let fut = async move {
            let path = parse_socket_path(&req)?;
            UnixStream::connect(path).await
        };

        Box::pin(fut)
    }

    fn poll_ready(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl Connection for UnixStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

fn parse_socket_path(uri: &Uri) -> Result<PathBuf, io::Error> {
    if uri.scheme_str() != Some("unix") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid URL, scheme must be unix",
        ));
    }

    if let Some(host) = uri.host() {
        let bytes = Vec::from_hex(host).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid URL, host must be a hex-encoded path",
            )
        })?;

        Ok(PathBuf::from(String::from_utf8_lossy(&bytes).into_owned()))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid URL, host must be present",
        ))
    }
}

/// Extension trait for constructing a hyper HTTP client over a Unix domain
/// socket.
pub trait UnixClientExt<B: Body + Send> {
    /// Construct a client which speaks HTTP over a Unix domain socket
    ///
    /// # Example
    /// ```
    /// use http_body_util::Full;
    /// use hyper::body::Bytes;
    /// use hyper_util::client::legacy::Client;
    /// use hyperlocal::{UnixClientExt, UnixConnector};
    ///
    /// let client: Client<UnixConnector, Full<Bytes>> = Client::unix();
    /// ```
    #[must_use]
    fn unix() -> Client<UnixConnector, B>
    where
        B::Data: Send,
    {
        Client::builder(TokioExecutor::new()).build(UnixConnector)
    }
}

impl<B: Body + Send> UnixClientExt<B> for Client<UnixConnector, B> {}
