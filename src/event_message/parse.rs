#[cfg(feature = "async")]
use super::serialization_info::SerializationInfo;
use super::{
    attachment::{Attachment, SourceSeal},
    payload_size::PayloadType,
    signed_event_message::{SignedNontransferableReceipt, SignedTransferableReceipt},
    AttachedSignaturePrefix, EventMessage, SignedEventMessage,
};
use crate::{derivation::attached_signature_code::b64_to_num, event::{event_data::EventData, sections::seal::EventSeal}, prefix::{
        parse::{
            attached_signature, attached_sn, basic_prefix, prefix, self_addressing_prefix,
            self_signing_prefix,
        },
        BasicPrefix, SelfSigningPrefix,
    }, state::IdentifierState};
use nom::{
    branch::*, bytes::complete::take, combinator::*, error::ErrorKind, multi::*, sequence::*,
};
use rmp_serde as serde_mgpk;
use serde::Deserialize;
use std::{convert::TryFrom, io::Cursor};

#[derive(Clone, Debug, PartialEq)]
pub struct DeserializedEvent<'a> {
    pub event_message: EventMessage,
    pub raw: &'a [u8],
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeserializedSignedEvent<'a> {
    pub deserialized_event: DeserializedEvent<'a>,
    pub signatures: Vec<AttachedSignaturePrefix>,
    pub attachment: Option<Attachment>,
}

// FIXME: detect payload type
impl From<DeserializedSignedEvent<'_>> for SignedEventMessage {
    fn from(de: DeserializedSignedEvent) -> SignedEventMessage {
        SignedEventMessage::new(
            &de.deserialized_event.event_message,
            PayloadType::MA,
            de.signatures,
            de.attachment,
        )
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
                event_message: event,
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
                event_message: event,
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
                event_message: event,
                raw: &s[..deser.get_ref().position() as usize],
            },
        )),
        _ => Err(nom::Err::Error((s, ErrorKind::IsNot))),
    }
}

pub fn message<'a>(s: &'a [u8]) -> nom::IResult<&[u8], DeserializedEvent> {
    alt((json_message, cbor_message, mgpk_message))(s).map(|d| (d.0, d.1))
}

// TESTED: OK
#[cfg(feature = "async")]
fn json_version(data: &[u8]) -> nom::IResult<&[u8], SerializationInfo> {
    match serde_json::from_slice(data) {
        Ok(vi) => Ok((data, vi)),
        _ => Err(nom::Err::Error((data, ErrorKind::IsNot))),
    }
}

// TODO: Requires testing
#[cfg(feature = "async")]
fn cbor_version(data: &[u8]) -> nom::IResult<&[u8], SerializationInfo> {
    match serde_cbor::from_slice(data) {
        Ok(vi) => Ok((data, vi)),
        _ => Err(nom::Err::Error((data, ErrorKind::IsNot))),
    }
}

// TODO: Requires testing
#[cfg(feature = "async")]
fn mgpk_version(data: &[u8]) -> nom::IResult<&[u8], SerializationInfo> {
    match serde_mgpk::from_slice(data) {
        Ok(vi) => Ok((data, vi)),
        _ => Err(nom::Err::Error((data, ErrorKind::IsNot))),
    }
}

#[cfg(feature = "async")]
pub(crate) fn version<'a>(data: &'a [u8]) -> nom::IResult<&[u8], SerializationInfo> {
    alt((json_version, cbor_version, mgpk_version))(data).map(|d| (d.0, d.1))
}

/// returns attached source seals
pub(crate) fn source_seal(s: &[u8]) -> nom::IResult<&[u8], Vec<SourceSeal>> {
    let (rest, sc) = b64_count(s)?;

    let (rest, attachment) = count(
        nom::sequence::tuple((attached_sn, self_addressing_prefix)),
        sc as usize,
    )(rest)?;
    Ok((
        rest,
        attachment
            .into_iter()
            .map(|(sn, digest)| SourceSeal::new(sn, digest))
            .collect(),
    ))
}

fn event_seal(s: &[u8]) -> nom::IResult<&[u8], EventSeal> {
    let (rest, identifier) = prefix(s)?;

    let (rest, sn) = attached_sn(rest)?;
    let (rest, event_digest) = self_addressing_prefix(rest)?;
    let seal = EventSeal {
        prefix: identifier,
        sn: u64::from(sn),
        event_digest,
    };

    Ok((rest, seal))
}

/// returst attached event seals
pub(crate) fn event_seals(s: &[u8]) -> nom::IResult<&[u8], Vec<EventSeal>> {
    let (rest, sc) = b64_count(s)?;

    count(event_seal, sc as usize)(rest)
}

pub(crate) fn b64_count(s: &[u8]) -> nom::IResult<&[u8], u16> {
    let (rest, t) = map(nom::bytes::complete::take(2u8), |b64_count| {
        b64_to_num(b64_count).map_err(|_| nom::Err::Failure((s, ErrorKind::IsNot)))
    })(s)?;

    Ok((rest, t?))
}

pub fn signatures(s: &[u8]) -> nom::IResult<&[u8], Vec<AttachedSignaturePrefix>> {
    let (rest, sc) = b64_count(s)?;
    count(attached_signature, sc as usize)(rest)
}

fn couplets(s: &[u8]) -> nom::IResult<&[u8], Vec<(BasicPrefix, SelfSigningPrefix)>> {
    let (rest, sc) = b64_count(s)?;

    count(
        nom::sequence::tuple((basic_prefix, self_signing_prefix)),
        sc as usize,
    )(rest)
}

fn attachment(s: &[u8]) -> nom::IResult<&[u8], Attachment> {
    let (rest, payload_type) = take(2u8)(s)?;
    let payload_type: PayloadType =
        PayloadType::try_from(std::str::from_utf8(payload_type).unwrap())
        .map_err(|_e| nom::Err::Failure((s, ErrorKind::IsNot)))?;
    match payload_type {
        PayloadType::MG => {
            let (rest, source_seals) = source_seal(rest)?;
            Ok((rest, Attachment::SealSourceCouplets(source_seals)))
        }
        PayloadType::MF => {
            let (rest, event_seals) = event_seals(rest)?;
            Ok((rest, Attachment::AttachedEventSeal(event_seals)))
        }
        PayloadType::MA => {
            let (rest, sigs) = signatures(rest)?;
            Ok((rest, Attachment::AttachedSignatures(sigs)))
        }
        PayloadType::MC => {
            let (rest, couplets) = couplets(rest)?;
            Ok((rest, Attachment::ReceiptCouplets(couplets)))
        }
        _ => todo!(),
    }
}

pub fn signed_message<'a>(s: &'a [u8]) -> nom::IResult<&[u8], Deserialized> {
    let (rest, e) = message(s)?;
    match e.event_message.event.event_data {
        EventData::Rct(_) => {
            let (rest, att) = attachment(rest)?;
            match att {
                // Should be nontransferable receipt
                Attachment::ReceiptCouplets(couplets) => Ok((
                    rest,
                    Deserialized::NontransferableRct(SignedNontransferableReceipt {
                        body: e.event_message,
                        couplets,
                    }),
                )),
                Attachment::AttachedEventSeal(_) | Attachment::AttachedSignatures(_) => {
                    // Should be transferable receipt
                    let (rest, second_att) = attachment(rest)?;

                    let (seals, sigs) = match (att, second_att) {
                        (
                            Attachment::AttachedEventSeal(seals),
                            Attachment::AttachedSignatures(sigs),
                        ) => Ok((seals, sigs)),
                        (
                            Attachment::AttachedSignatures(sigs),
                            Attachment::AttachedEventSeal(seals),
                        ) => Ok((seals, sigs)),
                        _ => {
                            // improper attachements
                            Err(nom::Err::Failure((s, ErrorKind::IsNot)))
                        }
                    }?;

                    Ok((
                        rest,
                        Deserialized::TransferableRct(SignedTransferableReceipt::new(
                            &e.event_message,
                            // TODO what if more than one?
                            seals.last().unwrap().to_owned(),
                            sigs,
                        )),
                    ))
                }
                _ => {
                    // Improper payload type
                    Err(nom::Err::Failure((s, ErrorKind::IsNot)))
                }
            }
        }
        EventData::Dip(_) | EventData::Drt(_) => {
            let (rest, (att1, att2)) = tuple((attachment, attachment))(rest)?;

            let (seals, sigs) = match (att1, att2) {
                (Attachment::SealSourceCouplets(seals), Attachment::AttachedSignatures(sigs)) => {
                    (seals, sigs)
                }
                (Attachment::AttachedSignatures(sigs), Attachment::SealSourceCouplets(seals)) => {
                    (seals, sigs)
                }
                _ => todo!(),
            };
            Ok((
                rest,
                Deserialized::Event(DeserializedSignedEvent {
                    deserialized_event: e,
                    signatures: sigs,
                    attachment: Some(Attachment::SealSourceCouplets(seals)),
                }),
            ))
        }
        _ => {
            let (rest, sigs) = attachment(rest)?;
            if let Attachment::AttachedSignatures(sigs) = sigs {
                Ok((
                    rest,
                    Deserialized::Event(DeserializedSignedEvent {
                        deserialized_event: e,
                        signatures: sigs,
                        attachment: None,
                    }),
                ))
            } else {
                todo!()
            }
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
                    .apply(&e.deserialized_event.event_message)
                    .map_err(|_| nom::Err::Error((s, ErrorKind::Verify)))?;
                if new_state
                    .current
                    .verify(e.deserialized_event.raw, &e.signatures)
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
fn test_b64_count() {
    assert_eq!(b64_count("AA".as_bytes()), Ok(("".as_bytes(), 0u16)));
    assert_eq!(b64_count("BA".as_bytes()), Ok(("".as_bytes(), 64u16)));
    assert_eq!(
        b64_count("ABextra data and stuff".as_bytes(),),
        Ok(("extra data and stuff".as_bytes(), 1u16))
    );
}

#[test]
fn test_sigs() {
    use crate::{derivation::self_signing::SelfSigning, prefix::AttachedSignaturePrefix};

    assert_eq!(
        attachment("-AABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes()),
        Ok(("".as_bytes(), Attachment::AttachedSignatures(vec![AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, vec![0u8; 64], 0)])))
    );

    assert!(attachment("-AABAA0Q7bqPvenjWXo_YIikMBKOg-pghLKwBi1Plm0PEqdv67L1_c6dq9bll7OFnoLp0a74Nw1cBGdjIPcu-yAllHAw".as_bytes()).is_ok());

    assert_eq!(
        attachment("-AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAextra data".as_bytes()),
        Ok(("extra data".as_bytes(), Attachment::AttachedSignatures(vec![
            AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, vec![0u8; 64], 0),
            AttachedSignaturePrefix::new(SelfSigning::Ed448, vec![0u8; 114], 2)
        ])))
    );

    assert_eq!(
        attachment("-AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes()),
        Ok(("".as_bytes(), Attachment::AttachedSignatures(vec![
            AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, vec![0u8; 64], 0),
            AttachedSignaturePrefix::new(SelfSigning::Ed448, vec![0u8; 114], 2)
        ])))
    )
}

#[test]
fn test_event() {
    let stream = br#"{"v":"KERI10JSON0000ed_","i":"E7WIS0e4Tx1PcQW5Um5s3Mb8uPSzsyPODhByXzgvmAdQ","s":"0","t":"icp","kt":"1","k":["Dpt7mGZ3y5UmhT1NLExb1IW8vMJ8ylQW3K44LfkTgAqE"],"n":"Erpltchg7BUv21Qz3ZXhOhVu63m7S7YbPb21lSeGYd90","bt":"0","b":[],"c":[],"a":[]}"#;
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.event_message.serialize().unwrap(), stream);

    // Inception event.
    let stream = r#"{"v":"KERI10JSON00011c_","i":"EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM","s":"0","t":"icp","kt":"1","k":["DaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"n":"EZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM","bt":"1","b":["DTNZH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8JZAo5CM"],"c":["EO"],"a":[]}"#.as_bytes();
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.event_message.serialize().unwrap(), stream);

    // Rotation event.
    let stream = r#"{"v":"KERI10JSON00011c_","i":"EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM","s":"1","t":"rot","p":"EULvaU6JR2nmwyZ-i0d8JZAoTNZH3YAfSVPzhzS6b5CM","kt":"1","k":["DaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"n":"EYAfSVPzhzZ-i0d8JZAoTNZH3ULvaU6JR2nmwyS6b5CM","bt":"1","br":["DH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8TNZJZAo5CM"],"ba":["DTNZH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8JZAo5CM"],"a":[{"i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"0","d":"ELvaU6Z-i0d8JJR2nmwyYAZAoTNZH3UfSVPzhzS6b5CM"}]}"#.as_bytes();
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.event_message.serialize().unwrap(), stream);

    // Interaction event without seals.
    let stream = r#"{"v":"KERI10JSON0000a3_","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"3","t":"ixn","p":"EHBaMkc2lTj-1qnIgSeD0GmYjw8Zv6EmCgGDVPedn3fI","a":[]}"#.as_bytes();
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.event_message.serialize().unwrap(), stream);

    // Interaction event with seal.
    let stream = r#"{"v":"KERI10JSON00011c_","i":"EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM","s":"2","t":"ixn","p":"EULvaU6JR2nmwyZ-i0d8JZAoTNZH3YAfSVPzhzS6b5CM","a":[{"i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"1","d":"ELvaU6Z-i0d8JJR2nmwyYAZAoTNZH3UfSVPzhzS6b5CM"}]}"#.as_bytes();
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.event_message.serialize().unwrap(), stream);

    // Delegated inception event.
    let stream = r#"{"v":"KERI10JSON000121_","i":"E-9tsnVcfUyXVQyBPGfntoL-xexf4Cldt_EPzHis2W4U","s":"0","t":"dip","kt":"1","k":["DuK1x8ydpucu3480Jpd1XBfjnCwb3dZ3x5b1CJmuUphA"],"n":"EWWkjZkZDXF74O2bOQ4H5hu4nXDlKg2m4CBEBkUxibiU","bt":"0","b":[],"c":[],"a":[],"di":"Eta8KLf1zrE5n-HZpgRAnDmxLASZdXEiU9u6aahqR8TI"}"#.as_bytes();
    let event = message(stream);
    assert_eq!(event.unwrap().1.event_message.serialize().unwrap(), stream);

    // // Delegated rotation event.
    let stream = r#"{"v":"KERI10JSON000122_","i":"E-9tsnVcfUyXVQyBPGfntoL-xexf4Cldt_EPzHis2W4U","s":"1","t":"drt","p":"E1x1JOub6oEQkxAxTNFu1Pma6y-lrbprNsaILHJHoPmY","kt":"1","k":["DTf6QZWoet154o9wvzeMuNhLQRr8JaAUeiC6wjB_4_08"],"n":"E8kyiXDfkE7idwWnAZQjHbUZMz-kd_yIMH0miptIFFPo","bt":"0","br":[],"ba":[],"a":[]}"#.as_bytes();
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.event_message.serialize().unwrap(), stream);
}

#[test]
fn test_attachement() {
    let attached_str = "-GAC0AAAAAAAAAAAAAAAAAAAAAAQE3fUycq1G-P1K1pL2OhvY6ZU-9otSa3hXiCcrxuhjyII0AAAAAAAAAAAAAAAAAAAAAAQE3fUycq1G-P1K1pL2OhvY6ZU-9otSa3hXiCcrxuhjyII";
    let (_rest, attached_sn_dig) = attachment(attached_str.as_bytes()).unwrap();
    assert_eq!(
        attached_sn_dig,
        Attachment::SealSourceCouplets(vec![
            SourceSeal {
                sn: 1,
                digest: "E3fUycq1G-P1K1pL2OhvY6ZU-9otSa3hXiCcrxuhjyII"
                    .parse()
                    .unwrap()
            },
            SourceSeal {
                sn: 1,
                digest: "E3fUycq1G-P1K1pL2OhvY6ZU-9otSa3hXiCcrxuhjyII"
                    .parse()
                    .unwrap()
            }
        ])
    );

    let attached_str = "-FABED9EB3sA5u2vCPOEmX3d7bEyHiSh7Xi8fjew2KMl3FQM0AAAAAAAAAAAAAAAAAAAAAAAEeGqW24EnxUgO_wfuFo6GR_vii-RNv5iGo8ibUrhe6Z0";
    let (_rest, seal) = attachment(attached_str.as_bytes()).unwrap();
    assert_eq!(
        seal,
        Attachment::AttachedEventSeal(vec![EventSeal {
            prefix: "ED9EB3sA5u2vCPOEmX3d7bEyHiSh7Xi8fjew2KMl3FQM"
                .parse()
                .unwrap(),
            sn: 0,
            event_digest: "EeGqW24EnxUgO_wfuFo6GR_vii-RNv5iGo8ibUrhe6Z0"
                .parse()
                .unwrap()
        },])
    );

    let attached_str = "-CABBed2Tpxc8KeCEWoq3_RKKRjU_3P-chSser9J4eAtAK6I0B8npsG58rX1ex73gaGe-jvRnw58RQGsDLzoSXaGn-kHRRNu6Kb44zXDtMnx-_8CjnHqskvDbz6pbEbed3JTOnCQ";
    let (_rest, seal) = attachment(attached_str.as_bytes()).unwrap();
    assert_eq!(seal, Attachment::ReceiptCouplets(
        vec![
            ("Bed2Tpxc8KeCEWoq3_RKKRjU_3P-chSser9J4eAtAK6I".parse().unwrap(), "0B8npsG58rX1ex73gaGe-jvRnw58RQGsDLzoSXaGn-kHRRNu6Kb44zXDtMnx-_8CjnHqskvDbz6pbEbed3JTOnCQ".parse().unwrap())
            ]
        )
    );
}

#[test]
fn test_stream1() {
    // taken from KERIPY: tests/core/test_eventing.py::test_kevery#1998
    let stream = br#"{"v":"KERI10JSON0000ed_","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","bt":"0","b":[],"c":[],"a":[]}-AABAAmagesCSY8QhYYHCJXEWpsGD62qoLt2uyT0_Mq5lZPR88JyS5UrwFKFdcjPqyKc_SKaKDJhkGWCk07k_kVkjyCA"#;

    let parsed = signed_message(stream).unwrap().1;

    match parsed {
        Deserialized::Event(signed_event) => {
            assert_eq!(
                signed_event.deserialized_event.raw.len(),
                signed_event
                    .deserialized_event
                    .event_message
                    .serialization_info
                    .size
            );

            assert!(signed_message(stream).is_ok());
            assert!(signed_event_stream_validate(stream).is_ok());
            let signed_event: SignedEventMessage = signed_event.into();
            let serialized_again = signed_event.serialize();
            assert!(serialized_again.is_ok());
            let stringified = String::from_utf8(serialized_again.unwrap()).unwrap();
            assert_eq!(stream, stringified.as_bytes())
        }
        _ => assert!(false),
    }
}

#[test]
fn test_stream2() {
    // taken from KERIPY: tests/core/test_eventing.py::test_multisig_digprefix#2244
    let stream = br#"{"v":"KERI10JSON00014b_","i":"EsiHneigxgDopAidk_dmHuiUJR3kAaeqpgOAj9ZZd4q8","s":"0","t":"icp","kt":"2","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"n":"E9izzBkXX76sqt0N-tfLzJeRqj0W56p4pDQ_ZqNCDpyw","bt":"0","b":[],"c":[],"a":[]}-AADAAhcaP-l0DkIKlJ87iIVcDx-m0iKPdSArEu63b-2cSEn9wXVGNpWw9nfwxodQ9G8J3q_Pm-AWfDwZGD9fobWuHBAAB6mz7zP0xFNBEBfSKG4mjpPbeOXktaIyX8mfsEa1A3Psf7eKxSrJ5Woj3iUB2AhhLg412-zkk795qxsK2xfdxBAACj5wdW-EyUJNgW0LHePQcSFNxW3ZyPregL4H2FoOrsPxLa3MZx6xYTh6i7YRMGY50ezEjV81hkI1Yce75M_bPCQ"#;
    assert!(signed_message(stream).is_ok());
    assert!(signed_event_stream_validate(stream).is_ok());

    let parsed = signed_message(stream).unwrap().1;

    match parsed {
        Deserialized::Event(signed_event) => {
            assert_eq!(
                signed_event.deserialized_event.raw.len(),
                signed_event
                    .deserialized_event
                    .event_message
                    .serialization_info
                    .size
            );

            assert!(signed_message(stream).is_ok());
            assert!(signed_event_stream_validate(stream).is_ok());
            let signed_event: SignedEventMessage = signed_event.into();
            let serialized_again = signed_event.serialize();
            assert!(serialized_again.is_ok());
            let stringified = String::from_utf8(serialized_again.unwrap()).unwrap();
            assert_eq!(stream, stringified.as_bytes())
        }
        _ => assert!(false),
    }
}

#[test]
fn test_signed_trans_receipt() {
    let trans_receipt_event = r#"{"v":"KERI10JSON000091_","i":"E7WIS0e4Tx1PcQW5Um5s3Mb8uPSzsyPODhByXzgvmAdQ","s":"0","t":"rct","d":"ErDNDBG7x2xYAH2i4AOnhVe44RS3lC1mRRdkyolFFHJk"}-FABENlofRlu2VPul-tjDObk6bTia2deG6NMqeFmsXhAgFvA0AAAAAAAAAAAAAAAAAAAAAAAE_MT0wsz-_ju_DVK_SaMaZT9ZE7pP4auQYeo2PDaw9FI-AABAA0Q7bqPvenjWXo_YIikMBKOg-pghLKwBi1Plm0PEqdv67L1_c6dq9bll7OFnoLp0a74Nw1cBGdjIPcu-yAllHAw"#;
    let msg = signed_message(trans_receipt_event.as_bytes());
    assert!(msg.is_ok());

    // Taken from keripy/core/test_witness.py
    let nontrans_rcp = r#"{"v":"KERI10JSON000091_","i":"EpU9D_puIW_QhgOf3WKUy-gXQnXeTQcJCO_Igcxi1YBg","s":"0","t":"rct","d":"EIt0xQQf-o-9E1B9VTDHiicQzVWk1CptvnewcnuhSd0M"}-CABB389hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd680BCZrTPLvG7sNaxtV8ZGdIHABFHCZ9FlnG6b4J6a9GcyzJIJOjuGNphW2zyC_WWU6CGMG7V52UeJxPqLpaYdP7Cg"#;
    // let nontrans_rcp = r#"{"v":"KERI10JSON000091_","i":"EpU9D_puIW_QhgOf3WKUy-gXQnXeTQcJCO_Igcxi1YBg","s":"0","t":"rct","d":"EIt0xQQf-o-9E1B9VTDHiicQzVWk1CptvnewcnuhSd0M"}-CABBljDbmdNfb63KOpGV4mmPKwyyp3OzDsRzpNrdL1BRQts0BM4bMcLjcDtD0fmLOGDx2oxBloc2FujbyllA7GuPLm-RQbyPPQr70_Y7DXzlWgs8gaYotUATeR-dj1ru9qFwADA"#;
    let msg = signed_message(nontrans_rcp.as_bytes());
    println!("{:?}", msg);
    assert!(msg.is_ok());

    // witness receipt not implemented yet
    // let witness_receipts = r#"{"v":"KERI10JSON000091_","i":"EpU9D_puIW_QhgOf3WKUy-gXQnXeTQcJCO_Igcxi1YBg","s":"0","t":"rct","d":"EIt0xQQf-o-9E1B9VTDHiicQzVWk1CptvnewcnuhSd0M"}-BADAACZrTPLvG7sNaxtV8ZGdIHABFHCZ9FlnG6b4J6a9GcyzJIJOjuGNphW2zyC_WWU6CGMG7V52UeJxPqLpaYdP7CgAB8npsG58rX1ex73gaGe-jvRnw58RQGsDLzoSXaGn-kHRRNu6Kb44zXDtMnx-_8CjnHqskvDbz6pbEbed3JTOnCQACM4bMcLjcDtD0fmLOGDx2oxBloc2FujbyllA7GuPLm-RQbyPPQr70_Y7DXzlWgs8gaYotUATeR-dj1ru9qFwADA"#;
    // let msg = signed_message(witness_receipts.as_bytes());
    // println!("{:?}", msg);
    // assert!(msg.is_ok());
}

#[test]
fn test_stream3() {
    // should fail to verify with incorrect signature
    let stream = br#"{"v":"KERI10JSON00012a_","i":"E4_CHZxqydVAvJEI7beqk3TZwUR92nQydi1nI8UqUTxk","s":"0","t":"icp","kt":"1","k":["DLfozZ0uGvLED22X3K8lX6ciwhl02jdjt1DQ_EHnJro0","C6KROFI5gWRXhAiIMiHLCDa-Oj09kmVMr2btCE96k_3g"],"n":"E99mhvP0pLkGtxymQkspRqcdoIFOqdigCf_F3rpg7rfk","bt":"0","b":[],"c":[],"a":[]}-AABAAlxZyoxbADu-x9Ho6EC7valjC4bNn7muWvqC_uAEBd1P9xIeOSxmcYdhyvBg1-o-25ebv66Q3Td5bZ730wqLjBA"#;

    assert!(signed_message(stream).is_ok());
    let result = signed_event_stream_validate(stream);
    assert!(!result.is_ok());
}

#[cfg(feature = "async")]
#[test]
fn test_version_parse() {
    let json = br#""KERI10JSON00014b_""#;
    let json_result = version(json);
    assert!(json_result.is_ok());
}