use std::io::Cursor;

use nom::{
    branch::alt,
    error::ErrorKind,
    multi::{fold_many0, many0},
};
use serde::Deserialize;

#[cfg(feature = "async")]
use crate::event_message::serialization_info::SerializationInfo;

use crate::{event::{Event, EventMessage}, event_parsing::{Attachment, SignedEventData, attachment::attachment, EventType}, event_message::CommonEvent}; 
#[cfg(feature = "query")]
use serde::Serialize;
#[cfg(feature = "query")]
use crate::query::Envelope;
use rmp_serde as serde_mgpk;


fn json_message<'a, D: Deserialize<'a> + CommonEvent>(s: &'a [u8]) -> nom::IResult<&[u8], EventMessage<D>> {
    let mut stream = serde_json::Deserializer::from_slice(s).into_iter::<EventMessage<D>>();
    match stream.next() {
        Some(Ok(event)) => Ok((&s[stream.byte_offset()..], event)),
        _ => Err(nom::Err::Error((s, ErrorKind::IsNot))),
    }
}

fn cbor_message<'a, D: Deserialize<'a> +  CommonEvent>(s: &'a [u8]) -> nom::IResult<&[u8], EventMessage<D>> {
    let mut stream = serde_cbor::Deserializer::from_slice(s).into_iter::<EventMessage<D>>();
    match stream.next() {
        Some(Ok(event)) => Ok((&s[stream.byte_offset()..], event)),
        _ => Err(nom::Err::Error((s, ErrorKind::IsNot))),
    }
}

fn mgpk_message<'a, D: Deserialize<'a> + CommonEvent>(s: &[u8]) -> nom::IResult<&[u8], EventMessage<D>> {
    let mut deser = serde_mgpk::Deserializer::new(Cursor::new(s));
    match Deserialize::deserialize(&mut deser) {
        Ok(event) => Ok((&s[deser.get_ref().position() as usize..], event)),
        _ => Err(nom::Err::Error((s, ErrorKind::IsNot))),
    }
}

pub fn message<'a, D: Deserialize<'a> + CommonEvent>(s: &'a [u8]) -> nom::IResult<&[u8], EventMessage<D>> {
    alt((json_message::<D>, cbor_message::<D>, mgpk_message::<D>))(s)

}

pub fn event_message(s: &[u8]) -> nom::IResult<&[u8], EventType> {
    message::<Event>(s)
        .map(|d| (d.0, EventType::KeyEvent(d.1)))

}

#[cfg(feature = "query")]
fn envelope<'a, D: Serialize + Deserialize<'a> + CommonEvent>(s: &'a [u8]) -> nom::IResult<&[u8], EventMessage<Envelope<D>>> {
    message::<Envelope<D>>(s)
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
    let (rest, event) = alt((event_message, reply_message, query_message))(s)?;
    #[cfg(not(feature = "query"))]
    let (rest, event) = event_message(s)?;
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
    // taken from KERIPY: tests/core/test_eventing.py::test_multisig_digprefix#2244
    let stream = br#"{"v":"KERI10JSON00014b_","i":"EsiHneigxgDopAidk_dmHuiUJR3kAaeqpgOAj9ZZd4q8","s":"0","t":"icp","kt":"2","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"n":"E9izzBkXX76sqt0N-tfLzJeRqj0W56p4pDQ_ZqNCDpyw","bt":"0","b":[],"c":[],"a":[]}-AADAAhcaP-l0DkIKlJ87iIVcDx-m0iKPdSArEu63b-2cSEn9wXVGNpWw9nfwxodQ9G8J3q_Pm-AWfDwZGD9fobWuHBAAB6mz7zP0xFNBEBfSKG4mjpPbeOXktaIyX8mfsEa1A3Psf7eKxSrJ5Woj3iUB2AhhLg412-zkk795qxsK2xfdxBAACj5wdW-EyUJNgW0LHePQcSFNxW3ZyPregL4H2FoOrsPxLa3MZx6xYTh6i7YRMGY50ezEjV81hkI1Yce75M_bPCQ"#;

    let parsed = signed_message(stream);
    assert!(parsed.is_ok());
}

#[test]
fn test_event() {
    // Inception event.
    let stream = br#"{"v":"KERI10JSON000120_","t":"icp","d":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"0","kt":"1","k":["DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"],"n":"E7FuL3Z_KBgt_QAwuZi1lUFNC69wvyHSxnMFUsKjZHss","bt":"0","b":[],"c":[],"a":[]}"#;
    let event = event_message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.serialize().unwrap(), stream);

    // Rotation event.
    let stream = br#"{"v":"KERI10JSON000155_","t":"rot","d":"EAntLipNnDDcGAJfGz9TStcJ8M19YLji3LPNVpXalwv4","i":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc","s":"1","p":"EO4Z11IVb8w4dUs4cGqYtp53dYKIV8j-mORGJ7wOdSN8","kt":"1","k":["DHgZa-u7veNZkqk2AxCnxrINGKfQ0bRiaf9FdA_-_49A"],"n":"EAXTvbATMnVRGjyC_VCNuXcPTxxpLanfzj14u3QMsD_U","bt":"0","br":[],"ba":[],"a":[]}"#; 

    let event = event_message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.serialize().unwrap(), stream);

    // Interaction event without seals.
    let stream = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"E4hrx06bab0CN3rZoT-9NMtidfOH8PnIP0IvqsuUQOZ0","i":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc","s":"2","p":"EAntLipNnDDcGAJfGz9TStcJ8M19YLji3LPNVpXalwv4","a":[]}"#;
    let event = event_message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.serialize().unwrap(), stream);

    // Interaction event with seal.
    let stream = br#"{"v":"KERI10JSON00013a_","t":"ixn","d":"E1_-icBrwC_HhxyFwsQLV6hZEbApOc_McGUjhLONpQuc","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"1","p":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","a":[{"i":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","s":"0","d":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI"}]}"#;
    let event = event_message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.serialize().unwrap(), stream);

    // Delegated inception event.
    let stream = br#"{"v":"KERI10JSON000154_","t":"dip","d":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","i":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","s":"0","kt":"1","k":["DuK1x8ydpucu3480Jpd1XBfjnCwb3dZ3x5b1CJmuUphA"],"n":"EWWkjZkZDXF74O2bOQ4H5hu4nXDlKg2m4CBEBkUxibiU","bt":"0","b":[],"c":[],"a":[],"di":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8"}"#;
    let event = event_message(stream);
    assert_eq!(event.unwrap().1.serialize().unwrap(), stream);

    // Delegated rotation event.
    let stream = br#"{"v":"KERI10JSON000155_","t":"drt","d":"ELEnIYF_rAsluR9TI_jh5Dizq61dCXjos22AGN0hiVjw","i":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","s":"1","p":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","kt":"1","k":["DTf6QZWoet154o9wvzeMuNhLQRr8JaAUeiC6wjB_4_08"],"n":"E8kyiXDfkE7idwWnAZQjHbUZMz-kd_yIMH0miptIFFPo","bt":"0","br":[],"ba":[],"a":[]}"#;
    let event = event_message(stream);
    assert!(event.is_ok());
    assert_eq!(event.unwrap().1.serialize().unwrap(), stream);
}

#[cfg(feature = "query")]
#[test]
fn test_qry() {
    use crate::query::query::QueryData;
    // taken from keripy keripy/tests/core/test_eventing.py::test_messegize (line 1462)
    let qry_event = r#"{"v":"KERI10JSON0000c9_","t":"qry","d":"E-WvgxrllmjGFhpn0oOiBkAVz3-dEm3bbiV_5qwj81xo","dt":"2021-01-01T00:00:00.000000+00:00","r":"log","rr":"","q":{"i":"DyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI"}}"#;
    let rest = "something more";
    let stream = [qry_event, rest].join("");

    let (extra, event): (_, EventMessage<Envelope<QueryData>>) = envelope(stream.as_bytes()).unwrap();

    assert_eq!(serde_json::to_string(&event).unwrap(), qry_event);
    assert_eq!(rest.as_bytes(), extra);
}

#[cfg(feature = "query")]
#[test]
fn test_signed_qry() {
    use nom::Needed;

    let stream = br#"{"v":"KERI10JSON000097_","t":"qry","dt":"2021-01-01T00:00:00.000000+00:00","r":"logs","rr":"","q":{"i":"EUrtK94nJesKGJaY_ymhz0mtkAjRsBonwEGydYBFCiXY"}}-VAj-HABEQJ9AtK25vIlgjOH0tDPCU7_S7Xw81sdH7K4cVCXCvSc-AABAAc5J03WH5U1803tOyjqMYdc_DJ9UfptVAounOpX170bUBdjf5fdU0iJxNjwgo1kCG_ufcXHfd4u5m3QxM85UjCQ"#;
    let se = signed_message(&stream[..stream.len() - 1]);
    assert!(matches!(se, Err(nom::Err::Incomplete(Needed::Size(1)))));
    let se = signed_message(stream);
    assert!(se.is_ok());
}

#[test]
fn test_signed_events_stream() {
    let kerl_str = br#"{"v":"KERI10JSON0000ed_","i":"DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk","s":"0","t":"icp","kt":"1","k":["DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk"],"n":"EGofBtQtAeDMOO3AA4QM0OHxKyGQQ1l2HzBOtrKDnD-o","bt":"0","b":[],"c":[],"a":[]}-AABAAxemWo-mppcRkiGSOXpVwh8CYeTSEJ-a0HDrCkE-TKJ-_76GX-iD7s4sbZ7j5fdfvOuTNyuFw3a797gwpnJ-NAg{"v":"KERI10JSON000122_","i":"DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk","s":"1","t":"rot","p":"EvZY9w3fS1h98tJeysdNQqT70XLLec4oso8kIYjfu2Ks","kt":"1","k":["DLqde_jCw-C3y0fTvXMXX5W7QB0188bMvXVkRcedgTwY"],"n":"EW5MfLjWGOUCIV1tQLKNBu_WFifVK7ksthNDoHP89oOc","bt":"0","br":[],"ba":[],"a":[]}-AABAAuQcoYU04XYzJxOPp4cxmvXbqVpGADfQWqPOzo1S6MajUl1sEWEL1Ry30jNXaV3-izvHRNROYtPm2LIuIimIFDg{"v":"KERI10JSON000122_","i":"DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk","s":"2","t":"rot","p":"EOi_KYKjP4hinuTfgtoYj5QBw_Q1ZrRtWFQDp0qsNuks","kt":"1","k":["De5pKs8wiP9bplyjspW9L62PEANoad-5Kum1uAllRxPY"],"n":"ERKagV0hID1gqZceLsOV3s7MjcoRmCaps2bPBHvVQPEQ","bt":"0","br":[],"ba":[],"a":[]}-AABAAPKIYNAm6nmz4cv37nvn5XMKRVzfKkVpJwMDt2DG-DqTJRCP8ehCeyDFJTdtvdJHjKqrnxE4Lfpll3iUzuQM4Aw{"v":"KERI10JSON000122_","i":"DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk","s":"3","t":"rot","p":"EVK1FbLl7yWTxOzPwk7vo_pQG5AumFoeSE51KapaEymc","kt":"1","k":["D2M5V_e23Pa0IAqqhNDKzZX0kRIMkJyW8_M-gT_Kw9sc"],"n":"EYJkIfnCYcMFVIEi-hMMIjBQfXcTqH_lGIIqMw4LaeOE","bt":"0","br":[],"ba":[],"a":[]}-AABAAsrKFTSuA6tEzqV0C7fEbeiERLdZpStZMCTvgDvzNMfa_Tn26ejFRZ_rDmovoo8xh0dH7SdMQ5B_FvwCx9E98Aw{"v":"KERI10JSON000098_","i":"DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk","s":"4","t":"ixn","p":"EY7VDg-9Gixr9rgH2VyWGvnnoebgTyT9oieHZIaiv2UA","a":[]}-AABAAqHtncya5PNnwSbMRegftJc1y8E4tMZwajVVj2-FmGmp82b2A7pY1vr7cv36m7wPRV5Dusf4BRa5moMlHUpSqDA"#;
    let (rest, messages) = signed_event_stream(kerl_str).unwrap();

    assert!(rest.is_empty());
    assert_eq!(messages.len(), 5);
}
