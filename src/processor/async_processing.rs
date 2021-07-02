use std::{
    future::Future,
    pin::Pin,
    path::Path,
};
use arrayref::array_ref;
use async_std::{io::{BufRead, BufReader, Read, Write}, task::{Context, Poll}};
use crate::{database::sled::SledEventDatabase, event_message::parse::version, keri::Keri, prefix::IdentifierPrefix, signer::CryptoBox};
use pin_project_lite::pin_project;

pub type Result<T> = std::result::Result<T, String>;

pub async fn process<'a, R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: Read + Write + Unpin + ?Sized
{
        pin_project! {
            struct Processor<'a, R> {
                #[pin]
                reader: R,
                #[pin]
                keri: Keri<'a, CryptoBox>,
                processed: usize
            }
        }

        impl<'a, R> Future for Processor<'a, R>
        where
            R: BufRead
        {
            type Output = Result<Vec<u8>>;
            // TODO: close stream if some timeout reached
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut this = self.project();
                loop {
                    // read all the stuff available so far from the stream
                    let buffer = futures_core::ready!(this.reader.as_mut().poll_fill_buf(cx)).map_err(|e| e.to_string())?;
                    // Reader closed - we're done
                    if buffer.is_empty() { return Poll::Ready(Ok(vec!())); }
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
                        // and apply it
                        let response = this.keri.as_mut().respond(sliced_message).map_err(|e| e.to_string())?;
                        // TODO: return response here
                        // store size of the processed data
                        *this.processed += msg_length;
                    }
                    // tell stream not to return processed data agin
                    this.reader.as_mut().consume(amt);
                }
                // Poll::Ready(Ok(response))
            }
        }

        let path = Path::new("./keri.db");
        let db = SledEventDatabase::new(path).map_err(|e| e.to_string())?;
        let cb = CryptoBox::new().map_err(|e| e.to_string())?;
        let keri = Keri::new(&db, cb, IdentifierPrefix::default()).map_err(|e| e.to_string())?;
        let processor = Processor {
            reader: BufReader::new(reader),
            keri,
            processed: 0,
        };
        processor.await
}


