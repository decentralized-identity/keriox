use std::{
    future::Future,
    pin::Pin,
    path::Path,
};
use async_std::{io::{BufRead, BufReader, Read}, task::{Context, Poll}};
use crate::{database::sled::SledEventDatabase, keri::Keri, prefix::IdentifierPrefix, signer::CryptoBox};
use pin_project_lite::pin_project;

pub type Result<T> = std::result::Result<T, String>;

pub async fn process<'a, R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: Read + Unpin + ?Sized
{
        pin_project! {
            struct Processor<'a, R> {
                #[pin]
                reader: R,
                #[pin]
                keri: Keri<'a, CryptoBox>,
            }
        }

        impl<'a, R> Future for Processor<'a, R>
        where
            R: BufRead
        {
            type Output = Result<Vec<u8>>;

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut this = self.project();
                let buffer = futures_core::ready!(this.reader.as_mut().poll_fill_buf(cx)).map_err(|e| e.to_string())?;
                if buffer.is_empty() {
                    return Poll::Ready(Err(String::from("empty message")));
                }
                let response = this.keri.as_mut().respond(buffer).map_err(|e| e.to_string())?;
                Poll::Ready(Ok(response))
            }
        }

        let path = Path::new("./keri.db");
        let db = SledEventDatabase::new(path).map_err(|e| e.to_string())?;
        let cb = CryptoBox::new().map_err(|e| e.to_string())?;
        let keri = Keri::new(&db, cb, IdentifierPrefix::default()).map_err(|e| e.to_string())?;
        let processor = Processor {
            reader: BufReader::new(reader),
            keri,
        };
            processor.await
}