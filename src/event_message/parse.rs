use super::{AttachedSignaturePrefix, EventMessage, SignedEventMessage};
use crate::{
    error::Error,
    prefix::{attached_signature::b64_to_num, parse::attached_signature},
    state::IdentifierState,
    util::dfs_serializer,
};
use nom::{branch::*, combinator::*, error::ErrorKind, multi::*, sequence::*};
use serde::{Deserialize, Deserializer, Serialize};
use serde_transcode::transcode;

fn json_message(s: &str) -> nom::IResult<&str, EventMessage> {
    let mut stream = serde_json::Deserializer::from_slice(s.as_bytes()).into_iter::<EventMessage>();
    match stream.next() {
        Some(Ok(event)) => Ok((&s[stream.byte_offset()..], event)),
        _ => Err(nom::Err::Error((s, ErrorKind::IsNot))),
    }
}

fn cbor_message(s: &str) -> nom::IResult<&str, EventMessage> {
    let mut stream = serde_cbor::Deserializer::from_slice(s.as_bytes()).into_iter::<EventMessage>();
    match stream.next() {
        Some(Ok(event)) => Ok((&s[stream.byte_offset()..], event)),
        _ => Err(nom::Err::Error((s, ErrorKind::IsNot))),
    }
}

fn message(s: &str) -> nom::IResult<&str, EventMessage> {
    alt((json_message, cbor_message))(s)
}

fn json_sed_block(s: &[u8]) -> Result<Vec<u8>, Error> {
    let mut res = Vec::with_capacity(128);
    transcode(
        &mut serde_json::Deserializer::from_slice(s),
        &mut dfs_serializer::Serializer::new(&mut res),
    )?;
    Ok(res)
}

fn cbor_sed_block(s: &[u8]) -> Result<Vec<u8>, Error> {
    let mut res = Vec::with_capacity(128);
    transcode(
        &mut serde_json::Deserializer::from_slice(s),
        &mut dfs_serializer::Serializer::new(&mut res),
    )?;
    Ok(res)
}

fn cbor_json_block(s: &[u8]) -> Result<String, Error> {
    let mut res = Vec::with_capacity(128);
    transcode(
        &mut serde_cbor::Deserializer::from_slice(s),
        &mut serde_json::Serializer::new(&mut res),
    )?;
    // serde-json guarentees correct utf-8 output
    Ok(String::from_utf8(res).unwrap())
}

fn json_cbor_block(s: &str) -> Result<Vec<u8>, Error> {
    let mut res = Vec::with_capacity(128);
    transcode(
        &mut serde_json::Deserializer::from_str(s),
        &mut serde_cbor::Serializer::new(&mut res),
    )?;
    Ok(res)
}

fn json_sed(s: &[u8]) -> nom::IResult<&[u8], Vec<u8>> {
    let mut stream = serde_json::Deserializer::from_slice(s).into_iter::<EventMessage>();
    match stream.next() {
        Some(Ok(_)) => Ok((
            &s[stream.byte_offset()..],
            json_sed_block(&s[..stream.byte_offset()])
                .map_err(|_| nom::Err::Error((&s[..stream.byte_offset()], ErrorKind::IsNot)))?,
        )),
        _ => Err(nom::Err::Error((s, ErrorKind::IsNot))),
    }
}

fn cbor_sed(s: &[u8]) -> nom::IResult<&[u8], Vec<u8>> {
    let mut stream = serde_cbor::Deserializer::from_slice(s).into_iter::<EventMessage>();
    match stream.next() {
        Some(Ok(_)) => Ok((
            &s[stream.byte_offset()..],
            cbor_sed_block(&s[..stream.byte_offset()])
                .map_err(|_| nom::Err::Error((s, ErrorKind::IsNot)))?,
        )),
        _ => Err(nom::Err::Error((s, ErrorKind::IsNot))),
    }
}

pub fn sed(s: &[u8]) -> nom::IResult<&[u8], Vec<u8>> {
    alt((json_sed, cbor_sed))(s)
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
    let (rest, (count, signatures)) = tuple((sig_count, many0(attached_signature)))(s)?;
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

pub fn signed_event_stream_validate(s: &str) -> nom::IResult<&str, IdentifierState> {
    let (rest, id) = fold_many1(
        signed_message,
        Ok(IdentifierState::default()),
        |acc, next| {
            Ok(acc?
                .verify_and_apply(&next)
                .map_err(|_| nom::Err::Error((s, ErrorKind::Verify)))?)
        },
    )(s)?;

    Ok((rest, id?))
}

#[test]
fn test_sigs() {
    use crate::prefix::SelfSigningPrefix;
    assert_eq!(sig_count("-AAA"), Ok(("", 0u16)));
    assert_eq!(sig_count("-ABA"), Ok(("", 64u16)));
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

#[test]
fn test_event() {
    let stream = r#"{"vs":"KERI10JSON000159_","pre":"ECui-E44CqN2U7uffCikRCp_YKLkPrA4jsTZ_A0XRLzc","sn":"0","ilk":"icp","sith":"2","keys":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"nxt":"Evhf3437ZRRnVhT0zOxo_rBX_GxpGoAnLuzrVlDK8ZdM","toad":"0","wits":[],"cnfg":[]}extra data"#;
    assert!(message(stream).is_ok())
}

#[test]
fn test_stream() {
    // taken from KERIPY: tests/core/test_eventing.py#903
    let stream = r#"{"vs":"KERI10JSON000159_","pre":"ECui-E44CqN2U7uffCikRCp_YKLkPrA4jsTZ_A0XRLzc","sn":"0","ilk":"icp","sith":"2","keys":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"nxt":"Evhf3437ZRRnVhT0zOxo_rBX_GxpGoAnLuzrVlDK8ZdM","toad":"0","wits":[],"cnfg":[]}-AADAAJ66nrRaNjltE31FZ4mELVGUMc_XOqOAOXZQjZCEAvbeJQ8r3AnccIe1aepMwgoQUeFdIIQLeEDcH8veLdud_DQABTQYtYWKh3ScYij7MOZz3oA6ZXdIDLRrv0ObeSb4oc6LYrR1LfkICfXiYDnp90tAdvaJX5siCLjSD3vfEM9ADDAACQTgUl4zF6U8hfDy8wwUva-HCAiS8LQuP7elKAHqgS8qtqv5hEj3aTjwE91UtgAX2oCgaw98BCYSeT5AuY1SpDA"#;

    assert!(signed_message(stream).is_ok());
    assert!(signed_event_stream(stream).is_ok());
    assert!(signed_event_stream_validate(stream).is_ok())
}

#[test]
fn test_sed_extraction() {
    let stream = r#"{"vs":"KERI10JSON000159_","pre":"ECui-E44CqN2U7uffCikRCp_YKLkPrA4jsTZ_A0XRLzc","sn":"0","ilk":"icp","sith":"2","keys":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"nxt":"Evhf3437ZRRnVhT0zOxo_rBX_GxpGoAnLuzrVlDK8ZdM","toad":"0","wits":[],"cnfg":[]}"#;

    assert!(sed(stream.as_bytes()).is_ok())
}
