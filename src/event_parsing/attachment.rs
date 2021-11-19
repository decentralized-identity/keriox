use std::convert::TryFrom;

use nom::{bytes::complete::take, combinator::map, error::ErrorKind, multi::count};

use crate::{derivation::attached_signature_code::b64_to_num, event::sections::seal::{EventSeal, SourceSeal}, event_message::{attachment::Attachment, payload_size::PayloadType}, prefix::{AttachedSignaturePrefix, BasicPrefix, SelfSigningPrefix, parse::{attached_signature, attached_sn, basic_prefix, prefix, self_addressing_prefix, self_signing_prefix}}};

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

pub fn attachment(s: &[u8]) -> nom::IResult<&[u8], Attachment> {
    let (rest, payload_type) = take(2u8)(s)?;
    let payload_type: PayloadType = PayloadType::try_from(
        std::str::from_utf8(payload_type)
        .map_err(|_e| nom::Err::Failure((s, ErrorKind::IsNot)))?,
    )
    // Can't parse payload type
    .map_err(|_e| nom::Err::Error((s, ErrorKind::IsNot)))?;
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