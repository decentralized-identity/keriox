use super::{
    AttachedSignaturePrefix, EventMessage, SignedEventMessage, SignedNontransferableReceipt,
};
use crate::{
    derivation::attached_signature_code::b64_to_num,
    error::Error,
    event::event_data::EventData,
    prefix::{
        parse::{attached_signature, basic_prefix, self_signing_prefix},
        BasicPrefix, SelfSigningPrefix,
    },
    state::IdentifierState,
    util::dfs_serializer,
};
use nom::{branch::*, combinator::*, error::ErrorKind, multi::*, sequence::*};
use serde_transcode::transcode;

#[derive(Clone, Debug)]
pub struct DeserializedEvent<'a> {
    pub event: EventMessage,
    pub raw: &'a [u8],
}

#[derive(Clone, Debug)]
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
    // Vrc's dont need raw bytes and have a normal structure, use SignedEventMessage
    Vrc(SignedEventMessage),
    // Rct's have an alternative appended signature structure, use SignedNontransferableReceipt
    Rct(SignedNontransferableReceipt),
}

fn json_message(s: &[u8]) -> nom::IResult<&[u8], DeserializedEvent> {
    let mut stream = serde_json::Deserializer::from_slice(s).into_iter::<EventMessage>();
    match stream.next() {
        Some(Ok(event)) => Ok((
            &s[stream.byte_offset()..],
            DeserializedEvent {
                event: event,
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
                event: event,
                raw: &s[..stream.byte_offset()],
            },
        )),
        _ => Err(nom::Err::Error((s, ErrorKind::IsNot))),
    }
}

pub fn message<'a>(s: &'a [u8]) -> nom::IResult<&[u8], DeserializedEvent> {
    alt((json_message, cbor_message))(s).map(|d| (d.0, d.1))
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

pub fn signed_message<'a>(s: &'a [u8]) -> nom::IResult<&[u8], Deserialized> {
    let (rest, e) = message(s)?;
    match e.event.event.event_data {
        EventData::Rct(_) => {
            let (extra, couplets) = couplets(rest)?;
            Ok((
                extra,
                Deserialized::Rct(SignedNontransferableReceipt {
                    body: e.event,
                    couplets,
                }),
            ))
        }
        EventData::Vrc(_) => {
            let (extra, signatures) = signatures(rest)?;
            Ok((
                extra,
                Deserialized::Vrc(SignedEventMessage {
                    event_message: e.event,
                    signatures,
                }),
            ))
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
    // Inception event.
    let stream = r#"{"v":"KERI10JSON00011c_","i":"EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM","s":"0","t":"icp","kt":"1","k":["DaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"n":"EZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM","wt":"1","w":["DTNZH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8JZAo5CM"],"c":["EO"]}"#.as_bytes();
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.event.serialize().unwrap(), stream);

    // Rotation event.
    // Event seal doesn't contain sn yet.
    // TODO repleace with commented after adding sn there.
    // let stream = r#"{"v":"KERI10JSON00011c_","i":"EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM","s":"1","t":"rot","p":"EULvaU6JR2nmwyZ-i0d8JZAoTNZH3YAfSVPzhzS6b5CM","kt":"1","k":["DaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"n":"EYAfSVPzhzZ-i0d8JZAoTNZH3ULvaU6JR2nmwyS6b5CM","wt":"1","wa":["DTNZH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8JZAo5CM"],"wr":["DH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8TNZJZAo5CM"],"a":[{"i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"0","d":"ELvaU6Z-i0d8JJR2nmwyYAZAoTNZH3UfSVPzhzS6b5CM"}]}"#.as_bytes();
    let stream =  r#"{"v":"KERI10JSON00011c_","i":"EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM","s":"1","t":"rot","p":"EULvaU6JR2nmwyZ-i0d8JZAoTNZH3YAfSVPzhzS6b5CM","kt":"1","k":["DaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"n":"EYAfSVPzhzZ-i0d8JZAoTNZH3ULvaU6JR2nmwyS6b5CM","wt":"1","wa":["DTNZH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8JZAo5CM"],"wr":["DH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8TNZJZAo5CM"],"a":[{"i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","d":"ELvaU6Z-i0d8JJR2nmwyYAZAoTNZH3UfSVPzhzS6b5CM"}]}"#.as_bytes();
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.event.serialize().unwrap(), stream);

    // Interaction event without seals.
    let stream = r#"{"v":"KERI10JSON0000a3_","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"3","t":"ixn","p":"EHBaMkc2lTj-1qnIgSeD0GmYjw8Zv6EmCgGDVPedn3fI","a":[]}"#.as_bytes();
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.event.serialize().unwrap(), stream);

    // Interaction event with seal.
    // Event seal doesn't contain sn yet.
    // TODO replace with commented after adding sn there.
    // let stream = r#"{"v":"KERI10JSON00011c_","i":"EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM","s":"2","t":"ixn","p":"EULvaU6JR2nmwyZ-i0d8JZAoTNZH3YAfSVPzhzS6b5CM","a":[{"i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"1","d":"ELvaU6Z-i0d8JJR2nmwyYAZAoTNZH3UfSVPzhzS6b5CM"}]}"#.as_bytes();
    let stream = r#"{"v":"KERI10JSON00011c_","i":"EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM","s":"2","t":"ixn","p":"EULvaU6JR2nmwyZ-i0d8JZAoTNZH3YAfSVPzhzS6b5CM","a":[{"i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","d":"ELvaU6Z-i0d8JJR2nmwyYAZAoTNZH3UfSVPzhzS6b5CM"}]}"#.as_bytes();
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.event.serialize().unwrap(), stream);

    // Delegated inception event.
    let stream = r#"{"v":"KERI10JSON00011c_","i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"0","t":"dip","kt":"1","k":["DaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"n":"EZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM","wt":"1","w":["DTNZH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8JZAo5CM"],"c":["DND"],"da":{"i":"EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM","s":"1","t":"rot","p":"E8JZAoTNZH3ULZ-i0dvaU6JR2nmwyYAfSVPzhzS6b5CM"}}"#.as_bytes();
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.event.serialize().unwrap(), stream);

    // Delegated rotation event.
    let stream = r#"{"v":"KERI10JSON00011c_","i":"EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM","s":"1","t":"drt","p":"EULvaU6JR2nmwyZ-i0d8JZAoTNZH3YAfSVPzhzS6b5CM","kt":"1","k":["DaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"n":"EYAfSVPzhzZ-i0d8JZAoTNZH3ULvaU6JR2nmwyS6b5CM","wt":"1","wa":["DTNZH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8JZAo5CM"],"wr":["DH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8TNZJZAo5CM"],"a":[],"da":{"i":"EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM","s":"1","t":"ixn","p":"E8JZAoTNZH3ULZ-i0dvaU6JR2nmwyYAfSVPzhzS6b5CM"}}"#.as_bytes();
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.event.serialize().unwrap(), stream);
}

#[test]
fn test_stream1() {
    // TODO stream probably should be taken from KERIPY 
    // but for now it is generated by KERIOX
    let stream =
    r#"{"v":"KERI10JSON0000e6_","i":"EWbXTxxh1CT1kMZ2v279u8g7s0JffBtjXniY2gV3glCw","s":"0","t":"icp","kt":"1","k":["DIeZhDExid_S9AwrNcN_hiIJoXGBmobk8EdYOqTvygJk"],"n":"EvAMP8tRppbB0UVuMJKAgwITit7SZqfqOKukuM1VIZzk","wt":"0","w":[],"c":[]}-AABAAjsX0P6mfUByeMmyERzx2ts52pxisOhTX47UddRUJXnoTtHHj4skkwVxaAXxahx8ZBDjVaY2RWifbuZdfdUHBDw"#.as_bytes();

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
    // generated by KERIOX
    let stream = r#"{"v":"KERI10JSON0000e6_","i":"Eu6mi6Mns13JuBnzsIf5InVa5VXKAT8NVzU8ze4BXbfE","s":"0","t":"icp","kt":"1","k":["DMen5nG7mAzmocZzPcxCiSCovBj-88SL2orv7NoQrq_c"],"n":"EiEo8G36FrkLz51YD1oHsqyBhEUNNB8NqH-cmYrqiKBo","wt":"0","w":[],"c":[]}-AABAAT5UoXR_kTOqpasER2UljDiljyXvUCvWsS1yieRocdbHiuA6ihwpVE0F2kgFbdYBqg4KknGpb90pNUAc-yEOrBA"#.as_bytes();

    assert!(signed_message(stream).is_ok());
    assert!(signed_event_stream_validate(stream).is_ok())
}

#[test]
fn test_stream3() {
    // should fail to verify with incorrect signature
    let stream = r#"{"v":"KERI10JSON00012a_","i":"E4_CHZxqydVAvJEI7beqk3TZwUR92nQydi1nI8UqUTxk","s":"0","t":"icp","kt":"1","k":["DLfozZ0uGvLED22X3K8lX6ciwhl02jdjt1DQ_EHnJro0","C6KROFI5gWRXhAiIMiHLCDa-Oj09kmVMr2btCE96k_3g"],"n":"E99mhvP0pLkGtxymQkspRqcdoIFOqdigCf_F3rpg7rfk","wt":"0","w":[],"c":[]}-AABAAlxZyoxbADu-x9Ho6EC7valjC4bNn7muWvqC_uAEBd1P9xIeOSxmcYdhyvBg1-o-25ebv66Q3Td5bZ730wqLjBA"#.as_bytes();

    assert!(signed_message(stream).is_ok());
    let result = signed_event_stream_validate(stream);
    assert!(!result.is_ok());
}

#[test]
fn test_sed_extraction() {
    let stream = r#"{"vs":"KERI10JSON000159_","pre":"ECui-E44CqN2U7uffCikRCp_YKLkPrA4jsTZ_A0XRLzc","sn":"0","ilk":"icp","sith":"2","keys":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"nxt":"Evhf3437ZRRnVhT0zOxo_rBX_GxpGoAnLuzrVlDK8ZdM","toad":"0","wits":[],"cnfg":[]}"#.as_bytes();

    // sed transcoding is not required until arbitrary content events are used
    // assert!(sed(stream.as_bytes()).is_ok())
}
