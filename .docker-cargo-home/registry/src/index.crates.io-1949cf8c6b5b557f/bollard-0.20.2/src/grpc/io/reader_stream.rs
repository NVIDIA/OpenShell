#![cfg(feature = "buildkit_providerless")]

use bollard_buildkit_proto::moby::buildkit::v1::BytesMessage;
use futures_core::stream::Stream;
use log::error;
use pin_project_lite::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::AsyncRead;

const DEFAULT_CAPACITY: usize = 4096;

pin_project! {
    #[derive(Debug)]
    pub struct ReaderStream<R> {
        #[pin]
        reader: Option<R>,
        buf: BytesMessage,
        capacity: usize,
    }
}

impl<R: AsyncRead> ReaderStream<R> {
    pub(crate) fn new(reader: R) -> Self {
        ReaderStream {
            reader: Some(reader),
            buf: BytesMessage { data: vec![] },
            capacity: DEFAULT_CAPACITY,
        }
    }

    pub(crate) fn with_capacity(reader: R, capacity: usize) -> Self {
        ReaderStream {
            reader: Some(reader),
            buf: BytesMessage {
                data: Vec::with_capacity(capacity),
            },
            capacity,
        }
    }
}

impl<R: AsyncRead> Stream for ReaderStream<R> {
    type Item = BytesMessage;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        use tokio_util::io::poll_read_buf;

        let this = self.as_mut().project();

        let reader = match this.reader.as_pin_mut() {
            Some(r) => r,
            None => return Poll::Ready(None),
        };

        if this.buf.data.capacity() == 0 {
            this.buf.data.reserve(*this.capacity);
        }

        match poll_read_buf(reader, cx, &mut this.buf.data) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                self.project().reader.set(None);
                // Reading into poll_read_buf and poll_read suggests this can't happen..
                error!("Reading from async reader failed: {err}");
                Poll::Ready(None)
            }
            Poll::Ready(Ok(0)) => {
                self.project().reader.set(None);
                Poll::Ready(None)
            }
            Poll::Ready(Ok(_)) => {
                let chunk = this.buf.data.split_off(0);
                Poll::Ready(Some(BytesMessage { data: chunk }))
            }
        }
    }
}
