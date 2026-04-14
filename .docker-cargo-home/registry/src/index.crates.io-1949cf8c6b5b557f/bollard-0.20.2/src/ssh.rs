use futures_util::FutureExt;
use hyper_util::rt::TokioIo;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

#[derive(Clone)]
pub(crate) struct SshConnector {
    keypair_path: Option<String>,
}

impl SshConnector {
    pub fn new() -> Self {
        Self { keypair_path: None }
    }

    pub fn with_keypair(keypair_path: String) -> Self {
        Self {
            keypair_path: Some(keypair_path),
        }
    }
}

pub(crate) struct SshStream {
    _child: openssh::Child<Arc<openssh::Session>>,
    stdin: Option<TokioIo<openssh::ChildStdin>>,
    stdout: TokioIo<openssh::ChildStdout>,
}

impl tower_service::Service<hyper::Uri> for SshConnector {
    type Response = SshStream;
    type Error = openssh::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, destination: hyper::Uri) -> Self::Future {
        let keypair_path = self.keypair_path.clone();

        async move {
            let authority = match destination.scheme() {
                Some(scheme) if scheme == "ssh" => destination.authority().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "Missing authority")
                }),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Invalid scheme {:?}", destination.scheme()),
                )),
            }
            .map_err(openssh::Error::Connect)?;

            let mut builder = openssh::SessionBuilder::default();

            if let Some(key_path) = keypair_path {
                builder.keyfile(key_path);
            }

            let (builder, destination) = builder.resolve(authority.as_str());
            let tempdir = builder.launch_master(destination).await?;
            let session = Arc::new(openssh::Session::new_process_mux(tempdir));

            let mut child = session
                .arc_command("docker")
                .arg("system")
                .arg("dial-stdio")
                .stdin(openssh::Stdio::piped())
                .stdout(openssh::Stdio::piped())
                .spawn()
                .await?;

            Ok(SshStream {
                stdin: Some(TokioIo::new(child.stdin().take().unwrap())),
                stdout: TokioIo::new(child.stdout().take().unwrap()),
                _child: child,
            })
        }
        .boxed()
    }
}

impl SshStream {
    fn stdin(self: Pin<&mut Self>) -> io::Result<Pin<&mut TokioIo<openssh::ChildStdin>>> {
        self.get_mut()
            .stdin
            .as_mut()
            .map(Pin::new)
            .ok_or_else(|| io::ErrorKind::BrokenPipe.into())
    }

    fn stdout(self: Pin<&mut Self>) -> Pin<&mut TokioIo<openssh::ChildStdout>> {
        Pin::new(&mut self.get_mut().stdout)
    }
}

impl hyper::rt::Read for SshStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        self.stdout().poll_read(cx, buf)
    }
}

impl hyper::rt::Write for SshStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.stdin()?.poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.stdin()?.poll_write_vectored(cx, bufs)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stdin()?.poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // currently, poll_shutdown does nothing.
        // https://github.com/tokio-rs/tokio/blob/b3a14483bf5efa1b5cf75af27f6ef0770f4c5689/tokio/src/process/unix/mod.rs#L314-L316
        ready!(self.as_mut().stdin()?.poll_shutdown(cx))?;
        // drop stdin to shutdown the input half.
        drop(self.get_mut().stdin.take());
        Poll::Ready(Ok(()))
    }
}

impl hyper_util::client::legacy::connect::Connection for SshStream {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
    }
}
