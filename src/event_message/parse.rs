use super::{
    AttachedSignaturePrefix, EventMessage, SignedEventMessage, SignedNontransferableReceipt,
    SignedTransferableReceipt,
};
use crate::{
    derivation::attached_signature_code::b64_to_num,
    error::Error,
    event::{event_data::EventData, sections::seal::EventSeal},
    prefix::{
        parse::{attached_signature, basic_prefix, event_seal, self_signing_prefix},
        BasicPrefix, SelfSigningPrefix,
    },
    state::IdentifierState,
};
use nom::{
    branch::*,
    bytes::complete::tag,
    combinator::*,
    error::{ErrorKind, ParseError},
    multi::*,
    sequence::*,
};
use rmp_serde as serde_mgpk;
use serde::Deserialize;
use std::io::Cursor;

#[derive(Clone, Debug, PartialEq)]
pub struct DeserializedEvent<'a> {
    pub event: EventMessage,
    pub raw: &'a [u8],
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeserializedSignedEvent<'a> {
    pub event: DeserializedEvent<'a>,
    pub signatures: Vec<AttachedSignaturePrefix>,
}

impl From<DeserializedSignedEvent<'_>> for SignedEventMessage {
    fn from(de: DeserializedSignedEvent) -> SignedEventMessage {
        SignedEventMessage::new(&de.event.event, de.signatures)
    }
}

#[derive(Clone, Debug)]
pub enum Deserialized<'a> {
    // Event verification requires raw bytes, so use DesrializedSignedEvent
    Event(DeserializedSignedEvent<'a>),
    // Rct's have an alternative appended signature structure,
    // use SignedNontransferableReceipt and SignedTransferableReceipt
    NontransferableRct(SignedNontransferableReceipt),
    TransferableRct(SignedTransferableReceipt),
}

fn json_message(s: &[u8]) -> nom::IResult<&[u8], DeserializedEvent> {
    let mut stream = serde_json::Deserializer::from_slice(s).into_iter::<EventMessage>();
    match stream.next() {
        Some(Ok(event)) => Ok((
            &s[stream.byte_offset()..],
            DeserializedEvent {
                event,
                raw: &s[..stream.byte_offset()],
            },
        )),
        _ => Err(nom::Err::Error((s, ErrorKind::IsNot))),
    }
}

fn cbor_message(s: &[u8]) -> nom::IResult<&[u8], DeserializedEvent> {
    let mut stream = serde_cbor::Deserializer::from_slice(s).into_iter::<EventMessage>();
    match stream.next() {
        Some(Ok(event)) => Ok((
            &s[stream.byte_offset()..],
            DeserializedEvent {
                event,
                raw: &s[..stream.byte_offset()],
            },
        )),
        _ => Err(nom::Err::Error((s, ErrorKind::IsNot))),
    }
}

fn mgpk_message(s: &[u8]) -> nom::IResult<&[u8], DeserializedEvent> {
    let mut deser = serde_mgpk::Deserializer::new(Cursor::new(s));
    match Deserialize::deserialize(&mut deser) {
        Ok(event) => Ok((
            &s[deser.get_ref().position() as usize..],
            DeserializedEvent {
                event,
                raw: &s[..deser.get_ref().position() as usize],
            },
        )),
        _ => Err(nom::Err::Error((s, ErrorKind::IsNot))),
    }
}

pub fn message<'a>(s: &'a [u8]) -> nom::IResult<&[u8], DeserializedEvent> {
    alt((json_message, cbor_message, mgpk_message))(s).map(|d| (d.0, d.1))
}

/// extracts the count from the sig count code
fn sig_count(s: &[u8]) -> nom::IResult<&[u8], u16> {
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
fn signatures(s: &[u8]) -> nom::IResult<&[u8], Vec<AttachedSignaturePrefix>> {
    let (rest, sc) = sig_count(s)?;
    count(attached_signature, sc as usize)(rest)
}

fn couplets(s: &[u8]) -> nom::IResult<&[u8], Vec<(BasicPrefix, SelfSigningPrefix)>> {
    let (rest, sc) = sig_count(s)?;
    count(
        nom::sequence::tuple((basic_prefix, self_signing_prefix)),
        sc as usize,
    )(rest)
}

fn transferable_receipt_attachement(s: &[u8]) -> nom::IResult<&[u8], (EventSeal, Vec<AttachedSignaturePrefix>)> {
    tuple((event_seal, signatures))(s)
}

pub fn signed_message<'a>(s: &'a [u8]) -> nom::IResult<&[u8], Deserialized> {
    let (rest, e) = message(s)?;
    match e.event.event.event_data {
        EventData::Rct(_) => {
            if let Ok((rest, couplets)) = couplets(rest) {
                Ok((
                    rest,
                    Deserialized::NontransferableRct(SignedNontransferableReceipt {
                        body: e.event,
                        couplets,
                    }),
                ))
            } else {
                transferable_receipt_attachement(&rest[1..]).map(|(rest, attachement)| {
                    (
                        rest,
                        Deserialized::TransferableRct(SignedTransferableReceipt {
                            body: e.event,
                            event_seal: attachement.0,
                            signatures: attachement.1,
                        }),
                    )
                })
            }
        }
        _ => {
            let (extra, signatures) = signatures(rest)?;
            Ok((
                extra,
                Deserialized::Event(DeserializedSignedEvent {
                    event: e,
                    signatures,
                }),
            ))
        }
    }
}

pub fn signed_event_stream(s: &[u8]) -> nom::IResult<&[u8], Vec<Deserialized>> {
    many0(signed_message)(s)
}

pub fn signed_event_stream_validate(s: &[u8]) -> nom::IResult<&[u8], IdentifierState> {
    let (rest, id) = fold_many1(
        signed_message,
        Ok(IdentifierState::default()),
        |acc, next| match next {
            Deserialized::Event(e) => {
                let new_state = acc?
                    .apply(&e.event.event)
                    .map_err(|_| nom::Err::Error((s, ErrorKind::Verify)))?;
                if new_state
                    .current
                    .verify(e.event.raw, &e.signatures)
                    .map_err(|_| nom::Err::Error((s, ErrorKind::Verify)))?
                {
                    Ok(new_state)
                } else {
                    Err(nom::Err::Error((s, ErrorKind::Verify)))
                }
            }
            // TODO this probably should not just skip non-events
            _ => acc,
        },
    )(s)?;

    Ok((rest, id?))
}

#[test]
fn test_sigs() {
    use crate::{derivation::self_signing::SelfSigning, prefix::AttachedSignaturePrefix};
    assert_eq!(sig_count("-AAA".as_bytes()), Ok(("".as_bytes(), 0u16)));
    assert_eq!(sig_count("-ABA".as_bytes()), Ok(("".as_bytes(), 64u16)));
    assert_eq!(
        sig_count("-AABextra data and stuff".as_bytes(),),
        Ok(("extra data and stuff".as_bytes(), 1u16))
    );

    assert_eq!(
        signatures("-AABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes()),
        Ok(("".as_bytes(), vec![AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, vec![0u8; 64], 0)]))
    );

    assert!(signatures("-AABAA0Q7bqPvenjWXo_YIikMBKOg-pghLKwBi1Plm0PEqdv67L1_c6dq9bll7OFnoLp0a74Nw1cBGdjIPcu-yAllHAw".as_bytes()).is_ok());
    // -AABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

    assert_eq!(
        signatures("-AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAextra data".as_bytes()),
        Ok(("extra data".as_bytes(), vec![
            AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, vec![0u8; 64], 0),
            AttachedSignaturePrefix::new(SelfSigning::Ed448, vec![0u8; 114], 2)
        ]))
    );

    assert_eq!(
        signatures("-AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes()),
        Ok(("".as_bytes(), vec![
            AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, vec![0u8; 64], 0),
            AttachedSignaturePrefix::new(SelfSigning::Ed448, vec![0u8; 114], 2)
        ]))
    )
}

#[test]
fn test_event() {
    let stream = br#"{"v":"KERI10JSON0000ed_","i":"E7WIS0e4Tx1PcQW5Um5s3Mb8uPSzsyPODhByXzgvmAdQ","s":"0","t":"icp","kt":"1","k":["Dpt7mGZ3y5UmhT1NLExb1IW8vMJ8ylQW3K44LfkTgAqE"],"n":"Erpltchg7BUv21Qz3ZXhOhVu63m7S7YbPb21lSeGYd90","wt":"0","w":[],"c":[]}"#;
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.event.serialize().unwrap(), stream);

    // Inception event.
    let stream = r#"{"v":"KERI10JSON00011c_","i":"EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM","s":"0","t":"icp","kt":"1","k":["DaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"n":"EZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM","wt":"1","w":["DTNZH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8JZAo5CM"],"c":["EO"]}"#.as_bytes();
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.event.serialize().unwrap(), stream);

    // Rotation event.
    let stream = r#"{"v":"KERI10JSON00011c_","i":"EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM","s":"1","t":"rot","p":"EULvaU6JR2nmwyZ-i0d8JZAoTNZH3YAfSVPzhzS6b5CM","kt":"1","k":["DaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"n":"EYAfSVPzhzZ-i0d8JZAoTNZH3ULvaU6JR2nmwyS6b5CM","wt":"1","wr":["DH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8TNZJZAo5CM"],"wa":["DTNZH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8JZAo5CM"],"a":[{"i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"0","d":"ELvaU6Z-i0d8JJR2nmwyYAZAoTNZH3UfSVPzhzS6b5CM"}]}"#.as_bytes();
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.event.serialize().unwrap(), stream);

    // Interaction event without seals.
    let stream = r#"{"v":"KERI10JSON0000a3_","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"3","t":"ixn","p":"EHBaMkc2lTj-1qnIgSeD0GmYjw8Zv6EmCgGDVPedn3fI","a":[]}"#.as_bytes();
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.event.serialize().unwrap(), stream);

    // Interaction event with seal.
    let stream = r#"{"v":"KERI10JSON00011c_","i":"EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM","s":"2","t":"ixn","p":"EULvaU6JR2nmwyZ-i0d8JZAoTNZH3YAfSVPzhzS6b5CM","a":[{"i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"1","d":"ELvaU6Z-i0d8JJR2nmwyYAZAoTNZH3UfSVPzhzS6b5CM"}]}"#.as_bytes();
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.event.serialize().unwrap(), stream);

    // Delegated inception event.
    let stream = r#"{"v":"KERI10JSON00011c_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"0","t":"dip","kt":"1","k":["DaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"n":"EZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM","wt":"1","w":["DTNZH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8JZAo5CM"],"c":["DND"],"da":{"i":"EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM","s":"1","t":"rot","p":"E8JZAoTNZH3ULZ-i0dvaU6JR2nmwyYAfSVPzhzS6b5CM"}}"#.as_bytes();
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.event.serialize().unwrap(), stream);

    // Delegated rotation event.
    let stream = r#"{"v":"KERI10JSON00011c_","i":"EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM","s":"1","t":"drt","p":"EULvaU6JR2nmwyZ-i0d8JZAoTNZH3YAfSVPzhzS6b5CM","kt":"1","k":["DaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"n":"EYAfSVPzhzZ-i0d8JZAoTNZH3ULvaU6JR2nmwyS6b5CM","wt":"1","wr":["DH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8TNZJZAo5CM"],"wa":["DTNZH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8JZAo5CM"],"a":[],"da":{"i":"EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM","s":"1","t":"ixn","p":"E8JZAoTNZH3ULZ-i0dvaU6JR2nmwyYAfSVPzhzS6b5CM"}}"#.as_bytes();
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.event.serialize().unwrap(), stream);
}

#[test]
fn test_stream1() {
    // taken from KERIPY: tests/core/test_eventing.py#906
    let stream = br#"{"v":"KERI10JSON0000e6_","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","wt":"0","w":[],"c":[]}-AABAAyIoOoziM1_fGb-1gKWY_LtlKiZIwuaJ5iPkYflmqOxxBn6MspbvCcLf8bF_uAgxCVLG1W4IMEhvDi_8rPORgDw"#;

    let parsed = signed_message(stream).unwrap().1;

    match parsed {
        Deserialized::Event(signed_event) => {
            assert_eq!(
                signed_event.event.raw.len(),
                signed_event.event.event.serialization_info.size
            );

            assert!(signed_message(stream).is_ok());
            assert!(signed_event_stream_validate(stream).is_ok())
        }
        _ => assert!(false),
    }
}

#[test]
fn test_stream2() {
    // taken from KERIPY: tests/core/test_eventing.py#1138
    let stream = br#"{"v":"KERI10JSON000144_","i":"EJPRBUSEdUuZnh9kRGg8y7uBJDxTGZdp4YeUSqBv5sEk","s":"0","t":"icp","kt":"2","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"n":"E9izzBkXX76sqt0N-tfLzJeRqj0W56p4pDQ_ZqNCDpyw","wt":"0","w":[],"c":[]}-AADAA74a3kHBjpaY2h3AzX8UursaGoW8kKU1rRLlMTYffMvKSTbhHHy96brGN2P6ehcmEW2nlUNZVuMf8zo6Qd8PkCgABIJfoSJejaDh1g-UZKkldxtTCwic7kB3s15EsDPKpm_6EhGcxVTt0AFXQUQMroKgKrGnxL0GP6gwEdmdu9dVRAgACtJFQBQiRX5iqWpJQntfAZTx6VIv_Ghydg1oB0QCq7s8D8LuKH5n1S5t8AbbQPXv6Paf7AVJRFv8lhCT5cdx3Bg"#;

    assert!(signed_message(stream).is_ok());
    assert!(signed_event_stream_validate(stream).is_ok())
}

#[test]
fn test_signed_message() {
    let trans_receipt_event = r#"{"v":"KERI10JSON000091_","i":"E7WIS0e4Tx1PcQW5Um5s3Mb8uPSzsyPODhByXzgvmAdQ","s":"0","t":"rct","d":"ErDNDBG7x2xYAH2i4AOnhVe44RS3lC1mRRdkyolFFHJk"}-FABENlofRlu2VPul-tjDObk6bTia2deG6NMqeFmsXhAgFvA0AAAAAAAAAAAAAAAAAAAAAAAE_MT0wsz-_ju_DVK_SaMaZT9ZE7pP4auQYeo2PDaw9FI-AABAA0Q7bqPvenjWXo_YIikMBKOg-pghLKwBi1Plm0PEqdv67L1_c6dq9bll7OFnoLp0a74Nw1cBGdjIPcu-yAllHAw"#;
    let msg = signed_message(trans_receipt_event.as_bytes());
    assert!(msg.is_ok())
}

#[test]
fn test_stream3() {
    // should fail to verify with incorrect signature
    let stream = br#"{"v":"KERI10JSON00012a_","i":"E4_CHZxqydVAvJEI7beqk3TZwUR92nQydi1nI8UqUTxk","s":"0","t":"icp","kt":"1","k":["DLfozZ0uGvLED22X3K8lX6ciwhl02jdjt1DQ_EHnJro0","C6KROFI5gWRXhAiIMiHLCDa-Oj09kmVMr2btCE96k_3g"],"n":"E99mhvP0pLkGtxymQkspRqcdoIFOqdigCf_F3rpg7rfk","wt":"0","w":[],"c":[]}-AABAAlxZyoxbADu-x9Ho6EC7valjC4bNn7muWvqC_uAEBd1P9xIeOSxmcYdhyvBg1-o-25ebv66Q3Td5bZ730wqLjBA"#;

    assert!(signed_message(stream).is_ok());
    let result = signed_event_stream_validate(stream);
    assert!(!result.is_ok());
}
