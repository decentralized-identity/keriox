use std::{
    future::Future,
    pin::Pin,
};
use async_std::{
    io::{BufRead, BufReader, Read},
    task::{Context, Poll},
};
use crate::{
    event_message::parse::message,
    state::IdentifierState,
};
use pin_project_lite::pin_project;

pub type Result<T> = std::result::Result<T, String>;

pub async fn process<R>(reader: &mut R) -> Result<()>
where
    R: Read + Unpin + ?Sized
{
        pin_project! {
            struct Processor<R> {
                #[pin]
                reader: R,
                #[pin]
                state: IdentifierState,
                processed: usize
            }
        }

        impl<R> Future for Processor<R>
        where
            R: BufRead
        {
            type Output = Result<()>;

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut this = self.project();
                loop {
                    let buffer = futures_core::ready!(this.reader.as_mut().poll_fill_buf(cx)).map_err(|e| e.to_string())?;
                    let amt = buffer.len();
                    if buffer.is_empty() {
                        if *this.processed == 0usize {
                            return Poll::Ready(Err(String::from("empty message")));
                        } else {
                            return Poll::Ready(Ok(()));
                        }
                    }

                    *this.processed += 1;
                    let message = message(buffer).map_err(|e| e.to_string())?;
                    let new_state = this.state.clone().apply(&message.1.event).map_err(|e| e.to_string())?;
                    *this.state.as_mut() = new_state;
                    this.reader.as_mut().consume(amt);
                }
            }
        }

        let processor = Processor {
            reader: BufReader::new(reader),
            state: IdentifierState::default(),
            processed: 0
        };
        processor.await
}