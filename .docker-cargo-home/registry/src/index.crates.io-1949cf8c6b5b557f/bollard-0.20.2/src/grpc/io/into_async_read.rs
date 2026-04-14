#![cfg(feature = "buildkit_providerless")]

use std::{
    cmp,
    pin::Pin,
    task::{Context, Poll},
};

use futures_core::TryStream;
use pin_project_lite::pin_project;
use tokio::io::AsyncRead;

pin_project! {
    #[derive(Debug)]
    pub struct IntoAsyncRead<St>
    where
        St: TryStream<Error = std::io::Error>,
        St::Ok: AsRef<[u8]>,
    {
        #[pin]
        stream: St,
        state: ReadState<St::Ok>,
    }
}

#[derive(Debug)]
enum ReadState<T: AsRef<[u8]>> {
    Ready { chunk: T, chunk_start: usize },
    PendingChunk,
    Eof,
}

impl<St> IntoAsyncRead<St>
where
    St: TryStream<Error = std::io::Error>,
    St::Ok: AsRef<[u8]>,
{
    pub(crate) fn new(stream: St) -> Self {
        Self {
            stream,
            state: ReadState::PendingChunk,
        }
    }
}

impl<St> AsyncRead for IntoAsyncRead<St>
where
    St: TryStream<Error = std::io::Error>,
    St::Ok: AsRef<[u8]>,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.project();

        loop {
            match this.state {
                ReadState::Ready { chunk, chunk_start } => {
                    let chunk = chunk.as_ref();
                    let len = cmp::min(buf.remaining(), chunk.len() - *chunk_start);

                    buf.put_slice(&chunk[*chunk_start..*chunk_start + len]);

                    *chunk_start += len;

                    if chunk.len() == *chunk_start {
                        *this.state = ReadState::PendingChunk;
                    }

                    return Poll::Ready(Ok(()));
                }
                ReadState::PendingChunk => {
                    match futures_core::ready!(this.stream.as_mut().try_poll_next(cx)) {
                        Some(Ok(chunk)) => {
                            if !chunk.as_ref().is_empty() {
                                *this.state = ReadState::Ready {
                                    chunk,
                                    chunk_start: 0,
                                };
                            }
                        }
                        Some(Err(err)) => {
                            *this.state = ReadState::Eof;
                            return Poll::Ready(Err(err));
                        }
                        None => {
                            *this.state = ReadState::Eof;
                            return Poll::Ready(Ok(()));
                        }
                    }
                }
                ReadState::Eof => {
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}
