use std::{
    future::Future,
    pin::Pin,
};
use async_std::{
    io::{BufRead, BufReader, Read, Write},
    task::{Context, Poll},
};
use crate::{
    event_message::parse::message,
    state::IdentifierState,
    error::Error,
};
use pin_project_lite::pin_project;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub async fn process<R, W>(reader: &mut R, writer: &mut W) -> Result<()>
    where
        R: Read + Unpin + ?Sized,
        W: Write + Unpin + ?Sized {

        pin_project! {
            struct Processor<R, W> {
                #[pin]
                reader: R,
                #[pin]
                writer: W,
                #[pin]
                state: IdentifierState,
            }
        }

        impl<R, W> Future for Processor<R, W>
        where
            R: BufRead,
            W: Write + Unpin {
            type Output = Result<()>;

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let this = self.project();
                loop {
                    let buffer = futures_core::ready!(this.reader.as_mut().poll_fill_buf(cx))?;
                    if buffer.is_empty() {
                        futures_core::ready!(this.writer.as_mut().poll_flush(cx))?;
                        return Poll::Ready(Ok(()));
                    }

                    let message = message(buffer)?;
                    let new_state = this.state.as_mut().apply(&message.1.event)?;
                    *this.state.as_mut() = new_state;
                    // TODO: what should be returned on successful message processing?
                    let i = futures_core::ready!(this.writer.as_mut().poll_write(cx, &1i32.to_ne_bytes()))?;
                    if i == 0 {
                        return Poll::Ready(Err(Box::new(Error::ZeroSendError)));
                    }
                    this.reader.as_mut().consume(buffer.len());
                }
            }
        }

        let processor = Processor {
            reader: BufReader::new(reader),
            writer,
            state: IdentifierState::default(),
        };
        processor.await
}