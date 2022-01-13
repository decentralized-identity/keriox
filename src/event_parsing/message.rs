use std::io::Cursor;

use nom::{
    branch::alt,
    error::ErrorKind,
    multi::{fold_many0, many0},
};
use serde::Deserialize;

#[cfg(feature = "async")]
use crate::event_message::serialization_info::SerializationInfo;

use crate::{event::{EventMessage, receipt::Receipt}, event_parsing::{Attachment, SignedEventData, attachment::attachment, EventType}, event_message::{Digestible, KeyEvent}}; 
#[cfg(feature = "query")]
use serde::Serialize;
#[cfg(feature = "query")]
use crate::query::Envelope;
#[cfg(feature = "query")]
use crate::event_message::{SaidEvent, Typeable};
use rmp_serde as serde_mgpk;


fn json_message<'a, D: Deserialize<'a> + Digestible>(s: &'a [u8]) -> nom::IResult<&[u8], EventMessage<D>> {
    let mut stream = serde_json::Deserializer::from_slice(s).into_iter::<EventMessage<D>>();
    match stream.next() {
        Some(Ok(event)) => Ok((&s[stream.byte_offset()..], event)),
        _ => Err(nom::Err::Error((s, ErrorKind::IsNot))),
    }
}

fn cbor_message<'a, D: Deserialize<'a>>(s: &'a [u8]) -> nom::IResult<&[u8], EventMessage<D>> {
    let mut stream = serde_cbor::Deserializer::from_slice(s).into_iter::<EventMessage<D>>();
    match stream.next() {
        Some(Ok(event)) => Ok((&s[stream.byte_offset()..], event)),
        _ => Err(nom::Err::Error((s, ErrorKind::IsNot))),
    }
}

fn mgpk_message<'a, D: Deserialize<'a>>(s: &[u8]) -> nom::IResult<&[u8], EventMessage<D>> {
    let mut deser = serde_mgpk::Deserializer::new(Cursor::new(s));
    match Deserialize::deserialize(&mut deser) {
        Ok(event) => Ok((&s[deser.get_ref().position() as usize..], event)),
        _ => Err(nom::Err::Error((s, ErrorKind::IsNot))),
    }
}

pub fn message<'a, D: Deserialize<'a> + Digestible>(s: &'a [u8]) -> nom::IResult<&[u8], EventMessage<D>> {
    alt((json_message::<D>, cbor_message::<D>, mgpk_message::<D>))(s)

}

pub fn key_event_message(s: &[u8]) -> nom::IResult<&[u8], EventType> {
    message::<KeyEvent>(s)
        .map(|d| (d.0, EventType::KeyEvent(d.1)))

}

pub fn receipt_message(s: &[u8]) -> nom::IResult<&[u8], EventType> {
    message::<Receipt>(s)
        .map(|d| (d.0, EventType::Receipt(d.1)))

}

#[cfg(feature = "query")]
fn envelope<'a, D: Serialize + Deserialize<'a> + Typeable>(s: &'a [u8]) -> nom::IResult<&[u8], EventMessage<SaidEvent<Envelope<D>>>> {
    message::<SaidEvent<Envelope<D>>>(s)
        .map(|d| (d.0, d.1))
}

#[cfg(feature = "query")]
pub fn query_message<'a>(s: &'a [u8]) -> nom::IResult<&[u8], EventType> {
    use crate::query::query::QueryData;

    envelope::<QueryData>(s).map(|d| (d.0, EventType::Qry(d.1)))
}

#[cfg(feature = "query")]
pub fn reply_message<'a>(s: &'a [u8]) -> nom::IResult<&[u8], EventType> {
    use crate::query::reply::ReplyData;

    envelope::<ReplyData>(s).map(|d| (d.0, EventType::Rpy(d.1)))
}

pub fn signed_message(s: &[u8]) -> nom::IResult<&[u8], SignedEventData> {
    #[cfg(feature = "query")]
    let (rest, event) = alt((key_event_message, reply_message, query_message, receipt_message))(s)?;
    #[cfg(not(feature = "query"))]
    let (rest, event) = alt((key_event_message, receipt_message))(s)?;
    let (rest, attachments): (&[u8], Vec<Attachment>) =
        fold_many0(attachment, vec![], |mut acc: Vec<_>, item| {
            acc.push(item);
            acc
        })(rest)?;
        
    Ok((
        rest,
        SignedEventData {
            deserialized_event: event,
            attachments,
        }))
}

pub fn signed_event_stream(s: &[u8]) -> nom::IResult<&[u8], Vec<SignedEventData>> {
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
    // taken from KERIPY: tests/core/test_eventing.py::test_multisig_digprefix#2255
    let stream = br#"{"v":"KERI10JSON00017e_","t":"icp","d":"ELYk-z-SuTIeDncLr6GhwVUKnv3n3F1bF18qkXNd2bpk","i":"ELYk-z-SuTIeDncLr6GhwVUKnv3n3F1bF18qkXNd2bpk","s":"0","kt":"2","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"n":"E9izzBkXX76sqt0N-tfLzJeRqj0W56p4pDQ_ZqNCDpyw","bt":"0","b":[],"c":[],"a":[]}-AADAA39j08U7pcU66OPKsaPExhBuHsL5rO1Pjq5zMgt_X6jRbezevis6YBUg074ZNKAGdUwHLqvPX_kse4buuuSUpAQABphobpuQEZ6EhKLhBuwgJmIQu80ZUV1GhBL0Ht47Hsl1rJiMwE2yW7-yi8k3idw2ahlpgdd9ka9QOP9yQmMWGAQACM7yfK1b86p1H62gonh1C7MECDCFBkoH0NZRjHKAEHebvd2_LLz6cpCaqKWDhbM2Rq01f9pgyDTFNLJMxkC-fAQ"#;
    let parsed = signed_message(stream);
    assert!(parsed.is_ok());
}

#[test]
fn test_key_event_parsing() {
    // Inception event.
    let stream = br#"{"v":"KERI10JSON000120_","t":"icp","d":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"0","kt":"1","k":["DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"],"n":"E7FuL3Z_KBgt_QAwuZi1lUFNC69wvyHSxnMFUsKjZHss","bt":"0","b":[],"c":[],"a":[]}"#;
    let event = key_event_message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.serialize().unwrap(), stream);

    // Rotation event.
    let stream = br#"{"v":"KERI10JSON000155_","t":"rot","d":"EAntLipNnDDcGAJfGz9TStcJ8M19YLji3LPNVpXalwv4","i":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc","s":"1","p":"EO4Z11IVb8w4dUs4cGqYtp53dYKIV8j-mORGJ7wOdSN8","kt":"1","k":["DHgZa-u7veNZkqk2AxCnxrINGKfQ0bRiaf9FdA_-_49A"],"n":"EAXTvbATMnVRGjyC_VCNuXcPTxxpLanfzj14u3QMsD_U","bt":"0","br":[],"ba":[],"a":[]}"#; 

    let event = key_event_message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.serialize().unwrap(), stream);

    // Interaction event without seals.
    let stream = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"E4hrx06bab0CN3rZoT-9NMtidfOH8PnIP0IvqsuUQOZ0","i":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc","s":"2","p":"EAntLipNnDDcGAJfGz9TStcJ8M19YLji3LPNVpXalwv4","a":[]}"#;
    let event = key_event_message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.serialize().unwrap(), stream);

    // Interaction event with seal.
    let stream = br#"{"v":"KERI10JSON00013a_","t":"ixn","d":"E1_-icBrwC_HhxyFwsQLV6hZEbApOc_McGUjhLONpQuc","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"1","p":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","a":[{"i":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","s":"0","d":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI"}]}"#;
    let event = key_event_message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.serialize().unwrap(), stream);

    // Delegated inception event.
    let stream = br#"{"v":"KERI10JSON000154_","t":"dip","d":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","i":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","s":"0","kt":"1","k":["DuK1x8ydpucu3480Jpd1XBfjnCwb3dZ3x5b1CJmuUphA"],"n":"EWWkjZkZDXF74O2bOQ4H5hu4nXDlKg2m4CBEBkUxibiU","bt":"0","b":[],"c":[],"a":[],"di":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8"}"#;
    let event = key_event_message(stream);
    assert_eq!(event.unwrap().1.serialize().unwrap(), stream);

    // Delegated rotation event.
    let stream = br#"{"v":"KERI10JSON000155_","t":"drt","d":"ELEnIYF_rAsluR9TI_jh5Dizq61dCXjos22AGN0hiVjw","i":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","s":"1","p":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","kt":"1","k":["DTf6QZWoet154o9wvzeMuNhLQRr8JaAUeiC6wjB_4_08"],"n":"E8kyiXDfkE7idwWnAZQjHbUZMz-kd_yIMH0miptIFFPo","bt":"0","br":[],"ba":[],"a":[]}"#;
    let event = key_event_message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.serialize().unwrap(), stream);
}

#[test]
fn test_receipt_parsing() {
     // Receipt event
    let stream = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EsZuhYAPBDnexP3SOl9YsGvWBrYkjYcRjomUYmCcLAYY","i":"EsZuhYAPBDnexP3SOl9YsGvWBrYkjYcRjomUYmCcLAYY","s":"0"}"#;
    let event = receipt_message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.serialize().unwrap(), stream);
}

#[cfg(feature = "query")]
#[test]
fn test_qry() {
    // taken from keripy keripy/tests/core/test_eventing.py::test_messegize (line 1462)
    let qry_event = r#"{"v":"KERI10JSON0000c9_","t":"qry","d":"E-WvgxrllmjGFhpn0oOiBkAVz3-dEm3bbiV_5qwj81xo","dt":"2021-01-01T00:00:00.000000+00:00","r":"log","rr":"","q":{"i":"DyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI"}}"#;
    let rest = "something more";
    let stream = [qry_event, rest].join("");

    let (_extra, event) = query_message(stream.as_bytes()).unwrap();
    assert!(matches!(event, EventType::Qry(_)));
    assert_eq!(event.serialize().unwrap(), qry_event.as_bytes());
}

#[cfg(feature = "query")]
#[test]
fn test_reply() {
    let rpy = r#"{"v":"KERI10JSON000292_","t":"rpy","d":"E_v_Syz2Bhh1WCKx9GBSpU4g9FqqxtSNPI_M2KgMC1yI","dt":"2021-01-01T00:00:00.000000+00:00","r":"/ksn/Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","a":{"v":"KERI10JSON0001d7_","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"3","p":"EYhzp9WCvSNFT2dVryQpVFiTzuWGbFNhVHNKCqAqBI8A","d":"EsL4LnyvTGBqdYC_Ute3ag4XYbu8PdCj70un885pMYpA","f":"3","dt":"2021-01-01T00:00:00.000000+00:00","et":"rot","kt":"1","k":["DrcAz_gmDTuWIHn_mOQDeSK_aJIRiw5IMzPD7igzEDb0"],"n":"E_Y2NMHE0nqrTQLe57VPcM0razmxdxRVbljRCSetdjjI","bt":"0","b":[],"c":[],"ee":{"s":"3","d":"EsL4LnyvTGBqdYC_Ute3ag4XYbu8PdCj70un885pMYpA","br":[],"ba":[]}}}"#;//-FABEt78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV80AAAAAAAAAAAAAAAAAAAAAAwEsL4LnyvTGBqdYC_Ute3ag4XYbu8PdCj70un885pMYpA-AABAAycUrU33S2856nVTuKNbxmGzDwkR9XYY5cXGnpyz4NZsrvt8AdOxfQfYcRCr_URFU9UrEsLFIFJEPoiUEuTbcCg"#;
    let rest = "something more";
    let stream = [rpy, rest].join("");

    let (_extra, event) = reply_message(stream.as_bytes()).unwrap();
    assert!(matches!(event, EventType::Rpy(_)));
}

#[cfg(feature = "query")]
#[test]
fn test_signed_qry() {
    use nom::Needed;

    // Taken from keripy/tests/core/test_eventing.py::test_messagize (line 1471)
    let stream = br#"{"v":"KERI10JSON0000c9_","t":"qry","d":"E-WvgxrllmjGFhpn0oOiBkAVz3-dEm3bbiV_5qwj81xo","dt":"2021-01-01T00:00:00.000000+00:00","r":"log","rr":"","q":{"i":"DyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI"}}-VAj-HABEZOIsLsfrVdBvULlg3Hg_Y1r-hadS82ZpglBLojPIQhg-AABAAuISeZIVO_wXjIrGJ-VcVMxr285OkKzAqVEQqVPFx8Ht2A9GQFB-zRA18J1lpqVphOnnXbTc51WR4uAvK90EHBg"#;
    let se = signed_message(&stream[..stream.len() - 1]);
    assert!(matches!(se, Err(nom::Err::Incomplete(Needed::Size(1)))));
    let se = signed_message(stream);
    assert!(se.is_ok());
}

#[test]
fn test_signed_events_stream() {
    // Taken from keripy/tests/core/test_kevery.py::test kevery
    let kerl_str= br#"{"v":"KERI10JSON000120_","t":"icp","d":"EG4EuTsxPiRM7soX10XXzNsS1KqXKUp8xsQ-kW_tWHoI","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"0","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","bt":"0","b":[],"c":[],"a":[]}-AABAA0aSisI4ZZTH_6JCqsvAsEpuf_Jq6bDbvPWj_eCDnAGbSARqYHipNs-9W7MHnwnMfIXwLpcoJkKGrQ-SiaklhAw{"v":"KERI10JSON000155_","t":"rot","d":"Ej30AgJV14mTTs427F3kILLrP_l03a27APg2FBO0-QtA","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"1","p":"EG4EuTsxPiRM7soX10XXzNsS1KqXKUp8xsQ-kW_tWHoI","kt":"1","k":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI"],"n":"E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI","bt":"0","br":[],"ba":[],"a":[]}-AABAAwoiqt07w2UInzzo2DmtwkBfqX1-tTO4cYk_7YdlbJ95qA7PO5sEUkER8fZySQMNCVh64ruAh1yoew3TikwVGAQ{"v":"KERI10JSON000155_","t":"rot","d":"EmtXXRjyz6IdeX4201BgXKRDBm74gGqJF2r2umMMAL6I","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"2","p":"Ej30AgJV14mTTs427F3kILLrP_l03a27APg2FBO0-QtA","kt":"1","k":["DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"n":"EKrLE2h2nh3ClyJNEjKaikHWT7G-ngimNpK-QgVQv9As","bt":"0","br":[],"ba":[],"a":[]}-AABAAW_RsDfAcHkknyzh9oeliH90KGPJEI8AP3rJPyuTnpVg8yOVtSIp_JFlyRwjV5SEQOqddAcRV6JtaQO8oXtWFCQ{"v":"KERI10JSON0000cb_","t":"ixn","d":"EY7E4RJXPe7FF1zQPbpSMIY-TYz9eAmNIhuprPYqTQ5o","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"3","p":"EmtXXRjyz6IdeX4201BgXKRDBm74gGqJF2r2umMMAL6I","a":[]}-AABAAlB0Ui5NHJpcifXUB6bAutmpZkhSgwxyI5jEZ2JGVBgTI02sC0Ugbq3q0EpOae7ruXW-eabUz2s0FAs26jGwVBg{"v":"KERI10JSON0000cb_","t":"ixn","d":"ENVzbZieVIjYLYkPWQy0gfua11KqdRG-oku5Ut8Dl6hU","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"4","p":"EY7E4RJXPe7FF1zQPbpSMIY-TYz9eAmNIhuprPYqTQ5o","a":[]}-AABAAWITFg460TXvYvxxzN62vpqpLs-vGgeGAbd-onY3DYxd5e3AljHh85pTum4Ha48F5dui9IVYqYvuYJCG8p8KvDw{"v":"KERI10JSON000155_","t":"rot","d":"E6wrLhilpPo4ePq7m7ZccEcKjwPD2q9mqzLUb_aO2Hi0","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"5","p":"ENVzbZieVIjYLYkPWQy0gfua11KqdRG-oku5Ut8Dl6hU","kt":"1","k":["DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ"],"n":"EhVTfJFfl6L0Z0432mDUxeaqB_hlWPJ2qUuzG95gEyJU","bt":"0","br":[],"ba":[],"a":[]}-AABAAnqz-vnMx1cqe_SkcIrlx092UhbYzvvkHXjtxfuNDDcqnVtH11_8ZPaWomn3n963_bFTjjRhJaAH1SK8LU7s1DA{"v":"KERI10JSON0000cb_","t":"ixn","d":"Ek9gvRbkCt-wlgQBoV1PGm2iI__gaPURtJ3YrNFsXLzE","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"6","p":"E6wrLhilpPo4ePq7m7ZccEcKjwPD2q9mqzLUb_aO2Hi0","a":[]}-AABAAwGGWMNDpu8t4NuF_3M0jnkn3P063oUHmluwRwsyCg5tIvu-BfwIJRruAsCKry4LaI84dJAfAT5KJnG8xz9lJCw"#;
    let (rest, messages) = signed_event_stream(kerl_str).unwrap();

    assert!(rest.is_empty());
    assert_eq!(messages.len(), 7);
}
