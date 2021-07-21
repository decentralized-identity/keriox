use std::{
    convert::TryFrom,
    future::Future,
    pin::Pin,
    sync:: Arc,
};
use arrayref::array_ref;
use pin_project_lite::pin_project;
use async_std::{channel::Sender, io::{
        Read,
        Write,
        BufRead,
        BufReader,
    }, task::{Context, Poll, block_on}};
use crate::{
    event_message::{
        parse::{version, sig_count},
        payload_size::PayloadType,
    },
    keri::Keri,
    signer::CryptoBox,
    prefix::IdentifierPrefix,
};
use bitpat::bitpat;

pub type Result<T> = std::result::Result<T, String>;

pub async fn process<R, W>(
    keri: Arc<Keri<CryptoBox>>,
    reader: &mut R,
    writer: &mut W,
    first_byte: u8,
    respond_to: Sender<(IdentifierPrefix, Vec<u8>)>)
    -> Result<()>
where
    R: Read + Unpin + ?Sized,
    W: Write + Unpin + ?Sized
{
        pin_project! {
            struct Processor<R, W> {
                #[pin]
                reader: R,
                #[pin]
                writer: W,
                #[pin]
                keri: Arc<Keri<CryptoBox>>,
                #[pin]
                respond_to: Sender<(IdentifierPrefix, Vec<u8>)>,
                first_byte: u8,
                processed: usize,
            }
        }

        impl<R, W> Future for Processor<R, W>
        where
            R: BufRead,
            W: Write + Unpin
        {
            type Output = Result<()>;
            // TODO: close stream if some timeout reached
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut this = self.project();
                // check if first byte has proper bits according to this:
                // https://github.com/decentralized-identity/keri/blob/master/kids/kid0001Comment.md#unique-start-bits
               if !bitpat!(_ _ _ _ _ 1 0 0)(*this.first_byte)
                && !bitpat!(_ _ _ _ _ 0 1 1 )(*this.first_byte)
                && !bitpat!(_ _ _ _ _ 1 0 1)(*this.first_byte)
                && !bitpat!(_ _ _ _ _ 1 1 0)(*this.first_byte) {
                   return Poll::Ready(Err(format!("triplet not recognized: {:#10b}", *this.first_byte)));
               }
                loop {
                    // read all the stuff available so far from the stream
                    let buffer = futures_core::ready!(this.reader.as_mut().poll_fill_buf(cx)).map_err(|e| e.to_string())?;
                    // Reader closed - we're done
                    // TODO: should this close underlying TCP connection?
                    if buffer.is_empty() { return Poll::Ready(Ok(())); }
                    // size of what we've received so far
                    let amt = buffer.len();
                    // not enough data arrived to read metadata - get more
                    if amt < 24usize { continue; } // - *this.processed
                    // parse everything we've received so far
                    //  might be more than one message!
                    while amt > *this.processed {
                        // parse out length of message from metadata
                        // TODO: verify if this works with cbor and msgpack, not just json
                        // mutable to increase by size of attached crypto material
                        let mut msg_length = match version(array_ref!(buffer, *this.processed + 5, 19usize)) {
                            Ok(ver) => ver.1.size,
                            Err(_) => return Poll::Ready(Err("not KERI message".into()))
                        };
                        // not enough data arrived to read full message - get more
                        if amt < msg_length { continue; }
                        // check for attached crypto material
                        else if amt > msg_length {
                            // look for prefix size
                            // if starts with '-0' == 8 chars
                            // else == 4 chars
                            // details: https://github.com/decentralized-identity/keri/blob/master/kids/kid0001Comment.md#framing-codes
                            if bitpat!(_ _ _ _ _ 0 0 1)(buffer[msg_length + 1])
                            || bitpat!(_ _ _ _ _ 0 1 0)(buffer[msg_length + 1]) {
                                if amt < msg_length + 2 { continue; } // not enough data to read framing code
                                let master_code = PayloadType::try_from(&slice_to_string(array_ref!(buffer, msg_length, 2))?[..])
                                    .map_err(|e| e.to_string())?;
                                let attachment_size = {
                                    let code = slice_to_string(&buffer[msg_length..msg_length + master_code.master_code_size(false)])?;
                                    let count = sig_count(code.as_bytes())
                                        .map_err(|e| e.to_string())?.1;
                                    count as usize * master_code.size()
                                };
                                // include base64 crypto attachments and master code length
                                msg_length += attachment_size + master_code.master_code_size(false);
                            } else if bitpat!(_ _ _ _ _ 1 1 1)(*this.first_byte) {
                                // parse binary crypto attachments
                                msg_length += binary_attachments_len();
                            }
                        } // TODO: if equal it might mean that no attachments or not yet arrived!
                        // parse arrived message
                        let sliced_message = &buffer[*this.processed..*this.processed + msg_length];
                        // and generate response
                        let response = this.keri.respond_single(sliced_message).map_err(|e| e.to_string())?;
                        // stream it back
                        futures_core::ready!(this.writer.as_mut().poll_write(cx, &response.1))
                            .map_err(|e| e.to_string())?;
                        // send responded message with identifier for sync purposes
                        block_on(this.respond_to.as_mut()
                            .send((response.0, sliced_message.to_vec())))
                            .map_err(|e| e.to_string())?;
                        // store size of the processed data
                        *this.processed += msg_length;
                    }
                    // tell stream not to return processed data agin
                    this.reader.as_mut().consume(amt);
                    // reset counter
                    *this.processed = 0;
                }
            }
        }

        // let path = Path::new("./keri.db");
        // let db = SledEventDatabase::new(path).map_err(|e| e.to_string())?;
        // let cb = CryptoBox::new().map_err(|e| e.to_string())?;
        // let keri = Keri::new(&db, cb, IdentifierPrefix::default()).map_err(|e| e.to_string())?;
        let processor = Processor {
            reader: BufReader::new(reader),
            writer,
            keri,
            respond_to,
            first_byte,
            processed: 0,
        };
        processor.await
}

fn binary_attachments_len() -> usize {
    todo!()
}

fn slice_to_string(data: &[u8]) -> Result<String> {
    String::from_utf8(data.to_vec())
        .map_err(|e| e.to_string())
}

