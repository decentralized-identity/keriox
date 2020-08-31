use super::{AttachedSignaturePrefix, EventMessage, SignedEventMessage};
use crate::prefix::attached_signature::{b64_to_num, parse_attached_signature::signature};
use nom::{branch::*, combinator::*, error::ErrorKind, multi::*, sequence::*};

fn json_message(s: &str) -> nom::IResult<&str, EventMessage> {
    let mut stream = serde_json::Deserializer::from_slice(s.as_bytes()).into_iter::<EventMessage>();
    match stream.next() {
        Some(Ok(event)) => Ok((&s[stream.byte_offset()..], event)),
        _ => Err(nom::Err::Failure((s, ErrorKind::IsNot))),
    }
}

fn cbor_message(s: &str) -> nom::IResult<&str, EventMessage> {
    let mut stream = serde_cbor::Deserializer::from_slice(s.as_bytes()).into_iter::<EventMessage>();
    match stream.next() {
        Some(Ok(event)) => Ok((&s[stream.byte_offset()..], event)),
        _ => Err(nom::Err::Failure((s, ErrorKind::IsNot))),
    }
}

fn message(s: &str) -> nom::IResult<&str, EventMessage> {
    alt((json_message, cbor_message))(s)
}

/// extracts the count from the sig count code
fn sig_count(s: &str) -> nom::IResult<&str, u16> {
    let (rest, t) = tuple((
        map_parser(
            nom::bytes::complete::take(2u8),
            tuple((
                nom::bytes::complete::tag("-"),
                nom::bytes::complete::tag("A"),
            )),
        ),
        map(nom::bytes::complete::take(2u8), |b64_count| {
            b64_to_num(b64_count).map_err(|_| nom::Err::Failure((s, ErrorKind::IsNot)))
        }),
    ))(s)?;

    Ok((rest, t.1?))
}

/// called on an attached signature stream starting with a sig count
fn signatures(s: &str) -> nom::IResult<&str, Vec<AttachedSignaturePrefix>> {
    let (rest, (count, signatures)) = tuple((sig_count, many0(signature)))(s)?;
    if count as usize != signatures.len() {
        Err(nom::Err::Error((s, ErrorKind::Count)))
    } else {
        Ok((rest, signatures))
    }
}

pub fn signed_message(s: &str) -> nom::IResult<&str, SignedEventMessage> {
    let (rest, t) = nom::sequence::tuple((message, signatures))(s)?;
    Ok((rest, SignedEventMessage::new(&t.0, t.1)))
}

pub fn signed_event_stream(s: &str) -> nom::IResult<&str, Vec<SignedEventMessage>> {
    many0(signed_message)(s)
}

#[test]
fn test() {
    use crate::prefix::SelfSigningPrefix;
    assert_eq!(sig_count("-AAA"), Ok(("", 0u16)));
    assert_eq!(
        sig_count("-AABextra data and stuff"),
        Ok(("extra data and stuff", 1u16))
    );

    assert_eq!(
            signatures("-AABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            Ok(("", vec![AttachedSignaturePrefix {
                index: 0,
                sig: SelfSigningPrefix::Ed25519Sha512([0u8; 64].to_vec())
            }]))
        );

    assert_eq!(
            signatures("-AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAextra data"),
            Ok(("extra data", vec![AttachedSignaturePrefix {
                index: 0,
                sig: SelfSigningPrefix::Ed25519Sha512([0u8; 64].to_vec())
            }, AttachedSignaturePrefix {
                index: 2,
                sig: SelfSigningPrefix::Ed448([0u8; 114].to_vec())
            }]))
        );

    assert_eq!(
            signatures("-AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            Ok(("", vec![AttachedSignaturePrefix {
                index: 0,
                sig: SelfSigningPrefix::Ed25519Sha512([0u8; 64].to_vec())
            }, AttachedSignaturePrefix {
                index: 2,
                sig: SelfSigningPrefix::Ed448([0u8; 114].to_vec())
            }]))
        )
}
