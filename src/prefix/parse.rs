use crate::{
    derivation::{
        attached_signature_code::{b64_to_num, AttachedSignatureCode},
        self_signing::SelfSigning,
    },
    prefix::{AttachedSignaturePrefix, SelfSigningPrefix},
};
use nom::{
    branch::*, bytes::complete::take, combinator::*, error::ErrorKind, multi::*, sequence::*,
};

// TODO this could be a lot nicer, but is currently written to be careful and "easy" to follow
pub fn attached_signature(s: &str) -> nom::IResult<&str, AttachedSignaturePrefix> {
    let (more, type_c) = take(1u8)(s)?;

    match type_c {
        "A" => {
            let (maybe_sig, index_c) = take(1u8)(more)?;

            let index =
                b64_to_num(index_c).map_err(|_| nom::Err::Error((index_c, ErrorKind::IsNot)))?;

            let (rest, sig_s) = take(86u8)(maybe_sig)?;

            let sig = base64::decode_config(sig_s, base64::URL_SAFE)
                .map_err(|_| nom::Err::Error((index_c, ErrorKind::IsNot)))?;

            Ok((
                rest,
                AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, sig, index),
            ))
        }
        "B" => {
            let (maybe_sig, index_c) = take(1u8)(more)?;

            let index =
                b64_to_num(index_c).map_err(|_| nom::Err::Error((index_c, ErrorKind::IsNot)))?;

            let (rest, sig_s) = take(86u8)(maybe_sig)?;

            let sig = base64::decode_config(sig_s, base64::URL_SAFE)
                .map_err(|_| nom::Err::Error((index_c, ErrorKind::IsNot)))?;

            Ok((
                rest,
                AttachedSignaturePrefix::new(SelfSigning::ECDSAsecp256k1Sha256, sig, index),
            ))
        }
        "0" => {
            let (maybe_count, type_c_2) = take(1u8)(more)?;
            match type_c_2 {
                "A" => {
                    let (maybe_sig, index_c) = take(2u8)(maybe_count)?;

                    let index = b64_to_num(index_c)
                        .map_err(|_| nom::Err::Error((index_c, ErrorKind::IsNot)))?;

                    let (rest, sig_s) = take(152u8)(maybe_sig)?;

                    let sig = base64::decode_config(sig_s, base64::URL_SAFE)
                        .map_err(|_| nom::Err::Error((index_c, ErrorKind::IsNot)))?;

                    Ok((
                        rest,
                        AttachedSignaturePrefix::new(SelfSigning::Ed448, sig, index),
                    ))
                }
                _ => Err(nom::Err::Error((type_c_2, ErrorKind::IsNot))),
            }
        }
        _ => Err(nom::Err::Error((type_c, ErrorKind::IsNot))),
    }
}

#[test]
fn test() {
    assert_eq!(
        attached_signature("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        Ok(("", AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, vec![0u8; 64], 0)))
    );

    assert_eq!(
        attached_signature("BCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        Ok(("AA", AttachedSignaturePrefix::new(SelfSigning::ECDSAsecp256k1Sha256, vec![0u8; 64], 2)))
    );
}
