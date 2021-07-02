use std::{
    future::Future,
    pin::Pin,
};
use arrayref::array_ref;
use async_std::{io::{BufRead, BufReader, Read, Write}, task::{Context, Poll}};
use crate::{
    event_message::parse::{message, version},
    state::IdentifierState,
};
use pin_project_lite::pin_project;

pub type Result<T> = std::result::Result<T, String>;

pub async fn process<R>(reader: &mut R) -> Result<()>
where
    R: Read + Write + Unpin + ?Sized
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
            // TODO: close stream if some timeout reached
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut this = self.project();
                loop {
                    // read all the stuff available so far from the stream
                    let buffer = futures_core::ready!(this.reader.as_mut().poll_fill_buf(cx)).map_err(|e| e.to_string())?;
                    // Reader closed - we're done
                    if buffer.is_empty() { return Poll::Ready(Ok(())); }
                    // size of what we've received so far
                    let amt = buffer.len();
                    // not enough data arrived to read metadata - get more
                    if amt - *this.processed < 19usize { continue; }
                    // parse everything we've received so far
                    //  might be more than one message!
                    while amt > *this.processed {
                        // parse out length of message from metadata
                        let msg_length = match version(array_ref!(buffer, *this.processed + 5, 19usize)) {
                            Ok(ver) => ver.1.size,
                            Err(_) => return Poll::Ready(Err("not KERI message".into()))
                        };
                        // not enough data arrived to read full message - get more
                        if amt < msg_length { continue; }
                        // parse arrived message
                        let sliced_message = &buffer[*this.processed..msg_length];
                        println!("{}", String::from_utf8(sliced_message.to_vec()).unwrap()); // TODO: remove
                        let message = message(sliced_message)
                            .map_err(|e| e.to_string())?;
                        // and apply it
                        let new_state = this.state.clone().apply(&message.1.event).map_err(|e| e.to_string())?;
                        *this.state.as_mut() = new_state;
                        // store size of the processed data
                        *this.processed += msg_length;
                    }
                    // tell stream not to return processed data agin
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


