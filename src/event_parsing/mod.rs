use std::io::Cursor;

use nom::{
    branch::alt,
    error::ErrorKind,
    multi::{fold_many0, many0},
};
use serde::Deserialize;

#[cfg(feature = "async")]
use crate::event_message::serialization_info::SerializationInfo;

use crate::{
    event::EventMessage,
    event_message::{parse::Attachment, parse::DeserializedSignedEvent},
};
use rmp_serde as serde_mgpk;
pub mod attachment;
pub mod pack;
pub mod payload_size;
pub mod prefix;

fn json_message(s: &[u8]) -> nom::IResult<&[u8], EventMessage> {
    let mut stream = serde_json::Deserializer::from_slice(s).into_iter::<EventMessage>();
    match stream.next() {
        Some(Ok(event)) => Ok((&s[stream.byte_offset()..], event)),
        _ => Err(nom::Err::Error((s, ErrorKind::IsNot))),
    }
}

fn cbor_message(s: &[u8]) -> nom::IResult<&[u8], EventMessage> {
    let mut stream = serde_cbor::Deserializer::from_slice(s).into_iter::<EventMessage>();
    match stream.next() {
        Some(Ok(event)) => Ok((&s[stream.byte_offset()..], event)),
        _ => Err(nom::Err::Error((s, ErrorKind::IsNot))),
    }
}

fn mgpk_message(s: &[u8]) -> nom::IResult<&[u8], EventMessage> {
    let mut deser = serde_mgpk::Deserializer::new(Cursor::new(s));
    match Deserialize::deserialize(&mut deser) {
        Ok(event) => Ok((&s[deser.get_ref().position() as usize..], event)),
        _ => Err(nom::Err::Error((s, ErrorKind::IsNot))),
    }
}

pub fn message<'a>(s: &'a [u8]) -> nom::IResult<&[u8], EventMessage> {
    alt((json_message, cbor_message, mgpk_message))(s).map(|d| (d.0, d.1))
}

pub fn signed_message<'a>(s: &'a [u8]) -> nom::IResult<&[u8], DeserializedSignedEvent> {
    let (rest, msg) = message(s)?;
    let (rest, attachments): (&[u8], Vec<Attachment>) =
        fold_many0(attachment::attachment, vec![], |mut acc: Vec<_>, item| {
            acc.push(item);
            acc
        })(rest)?;

    Ok((
        rest,
        DeserializedSignedEvent {
            deserialized_event: msg,
            attachments,
        },
    ))
}

pub fn signed_event_stream(s: &[u8]) -> nom::IResult<&[u8], Vec<DeserializedSignedEvent>> {
    many0(signed_message)(s)
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

#[cfg(feature = "async")]
#[test]
fn test_version_parse() {
    let json = br#""KERI10JSON00014b_""#;
    let json_result = version(json);
    assert!(json_result.is_ok());
}

#[test]
fn test_signed_event() {
    // taken from KERIPY: tests/core/test_eventing.py::test_multisig_digprefix#2244
    let stream = br#"{"v":"KERI10JSON00014b_","i":"EsiHneigxgDopAidk_dmHuiUJR3kAaeqpgOAj9ZZd4q8","s":"0","t":"icp","kt":"2","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"n":"E9izzBkXX76sqt0N-tfLzJeRqj0W56p4pDQ_ZqNCDpyw","bt":"0","b":[],"c":[],"a":[]}-AADAAhcaP-l0DkIKlJ87iIVcDx-m0iKPdSArEu63b-2cSEn9wXVGNpWw9nfwxodQ9G8J3q_Pm-AWfDwZGD9fobWuHBAAB6mz7zP0xFNBEBfSKG4mjpPbeOXktaIyX8mfsEa1A3Psf7eKxSrJ5Woj3iUB2AhhLg412-zkk795qxsK2xfdxBAACj5wdW-EyUJNgW0LHePQcSFNxW3ZyPregL4H2FoOrsPxLa3MZx6xYTh6i7YRMGY50ezEjV81hkI1Yce75M_bPCQ"#;

    let parsed = signed_message(stream);
    assert!(parsed.is_ok());
}

#[test]
fn test_event() {
    let stream = br#"{"v":"KERI10JSON0000ed_","i":"E7WIS0e4Tx1PcQW5Um5s3Mb8uPSzsyPODhByXzgvmAdQ","s":"0","t":"icp","kt":"1","k":["Dpt7mGZ3y5UmhT1NLExb1IW8vMJ8ylQW3K44LfkTgAqE"],"n":"Erpltchg7BUv21Qz3ZXhOhVu63m7S7YbPb21lSeGYd90","bt":"0","b":[],"c":[],"a":[]}"#;
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.serialize().unwrap(), stream);

    // Inception event.
    let stream = r#"{"v":"KERI10JSON00011c_","i":"EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM","s":"0","t":"icp","kt":"1","k":["DaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"n":"EZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM","bt":"1","b":["DTNZH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8JZAo5CM"],"c":["EO"],"a":[]}"#.as_bytes();
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.serialize().unwrap(), stream);

    // Rotation event.
    let stream = r#"{"v":"KERI10JSON00011c_","i":"EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM","s":"1","t":"rot","p":"EULvaU6JR2nmwyZ-i0d8JZAoTNZH3YAfSVPzhzS6b5CM","kt":"1","k":["DaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"n":"EYAfSVPzhzZ-i0d8JZAoTNZH3ULvaU6JR2nmwyS6b5CM","bt":"1","br":["DH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8TNZJZAo5CM"],"ba":["DTNZH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8JZAo5CM"],"a":[{"i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"0","d":"ELvaU6Z-i0d8JJR2nmwyYAZAoTNZH3UfSVPzhzS6b5CM"}]}"#.as_bytes();
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.serialize().unwrap(), stream);

    // Interaction event without seals.
    let stream = r#"{"v":"KERI10JSON0000a3_","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"3","t":"ixn","p":"EHBaMkc2lTj-1qnIgSeD0GmYjw8Zv6EmCgGDVPedn3fI","a":[]}"#.as_bytes();
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.serialize().unwrap(), stream);

    // Interaction event with seal.
    let stream = r#"{"v":"KERI10JSON00011c_","i":"EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM","s":"2","t":"ixn","p":"EULvaU6JR2nmwyZ-i0d8JZAoTNZH3YAfSVPzhzS6b5CM","a":[{"i":"EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8","s":"1","d":"ELvaU6Z-i0d8JJR2nmwyYAZAoTNZH3UfSVPzhzS6b5CM"}]}"#.as_bytes();
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.serialize().unwrap(), stream);

    // Delegated inception event.
    let stream = r#"{"v":"KERI10JSON000121_","i":"E-9tsnVcfUyXVQyBPGfntoL-xexf4Cldt_EPzHis2W4U","s":"0","t":"dip","kt":"1","k":["DuK1x8ydpucu3480Jpd1XBfjnCwb3dZ3x5b1CJmuUphA"],"n":"EWWkjZkZDXF74O2bOQ4H5hu4nXDlKg2m4CBEBkUxibiU","bt":"0","b":[],"c":[],"a":[],"di":"Eta8KLf1zrE5n-HZpgRAnDmxLASZdXEiU9u6aahqR8TI"}"#.as_bytes();
    let event = message(stream);
    assert_eq!(event.unwrap().1.serialize().unwrap(), stream);

    // // Delegated rotation event.
    let stream = r#"{"v":"KERI10JSON000122_","i":"E-9tsnVcfUyXVQyBPGfntoL-xexf4Cldt_EPzHis2W4U","s":"1","t":"drt","p":"E1x1JOub6oEQkxAxTNFu1Pma6y-lrbprNsaILHJHoPmY","kt":"1","k":["DTf6QZWoet154o9wvzeMuNhLQRr8JaAUeiC6wjB_4_08"],"n":"E8kyiXDfkE7idwWnAZQjHbUZMz-kd_yIMH0miptIFFPo","bt":"0","br":[],"ba":[],"a":[]}"#.as_bytes();
    let event = message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.serialize().unwrap(), stream);
}

#[test]
fn test_signed_events_stream() {
    let kerl_str = br#"{"v":"KERI10JSON0000ed_","i":"DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk","s":"0","t":"icp","kt":"1","k":["DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk"],"n":"EGofBtQtAeDMOO3AA4QM0OHxKyGQQ1l2HzBOtrKDnD-o","bt":"0","b":[],"c":[],"a":[]}-AABAAxemWo-mppcRkiGSOXpVwh8CYeTSEJ-a0HDrCkE-TKJ-_76GX-iD7s4sbZ7j5fdfvOuTNyuFw3a797gwpnJ-NAg{"v":"KERI10JSON000122_","i":"DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk","s":"1","t":"rot","p":"EvZY9w3fS1h98tJeysdNQqT70XLLec4oso8kIYjfu2Ks","kt":"1","k":["DLqde_jCw-C3y0fTvXMXX5W7QB0188bMvXVkRcedgTwY"],"n":"EW5MfLjWGOUCIV1tQLKNBu_WFifVK7ksthNDoHP89oOc","bt":"0","br":[],"ba":[],"a":[]}-AABAAuQcoYU04XYzJxOPp4cxmvXbqVpGADfQWqPOzo1S6MajUl1sEWEL1Ry30jNXaV3-izvHRNROYtPm2LIuIimIFDg"#; //{"v":"KERI10JSON000122_","i":"DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk","s":"2","t":"rot","p":"EOi_KYKjP4hinuTfgtoYj5QBw_Q1ZrRtWFQDp0qsNuks","kt":"1","k":["De5pKs8wiP9bplyjspW9L62PEANoad-5Kum1uAllRxPY"],"n":"ERKagV0hID1gqZceLsOV3s7MjcoRmCaps2bPBHvVQPEQ","bt":"0","br":[],"ba":[],"a":[]}-AABAAPKIYNAm6nmz4cv37nvn5XMKRVzfKkVpJwMDt2DG-DqTJRCP8ehCeyDFJTdtvdJHjKqrnxE4Lfpll3iUzuQM4Aw{"v":"KERI10JSON000122_","i":"DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk","s":"3","t":"rot","p":"EVK1FbLl7yWTxOzPwk7vo_pQG5AumFoeSE51KapaEymc","kt":"1","k":["D2M5V_e23Pa0IAqqhNDKzZX0kRIMkJyW8_M-gT_Kw9sc"],"n":"EYJkIfnCYcMFVIEi-hMMIjBQfXcTqH_lGIIqMw4LaeOE","bt":"0","br":[],"ba":[],"a":[]}-AABAAsrKFTSuA6tEzqV0C7fEbeiERLdZpStZMCTvgDvzNMfa_Tn26ejFRZ_rDmovoo8xh0dH7SdMQ5B_FvwCx9E98Aw{"v":"KERI10JSON000098_","i":"DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk","s":"4","t":"ixn","p":"EY7VDg-9Gixr9rgH2VyWGvnnoebgTyT9oieHZIaiv2UA","a":[]}-AABAAqHtncya5PNnwSbMRegftJc1y8E4tMZwajVVj2-FmGmp82b2A7pY1vr7cv36m7wPRV5Dusf4BRa5moMlHUpSqDA"#;
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  // Process kerl
    let (rest, messages) = signed_event_stream(kerl_str).unwrap();

    assert!(rest.is_empty());
    assert_eq!(messages.len(), 2);
}
