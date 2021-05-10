use crate::{derivation::{
        attached_signature_code::b64_to_num,
        basic::Basic,
        self_signing::SelfSigning,
        DerivationCode,
    }, keys::Key, prefix::{AttachedSignaturePrefix, BasicPrefix, SelfSigningPrefix}};
use nom::{
    bytes::complete::take, error::ErrorKind,
};

// TODO this could be a lot nicer, but is currently written to be careful and "easy" to follow
pub fn attached_signature(s: &[u8]) -> nom::IResult<&[u8], AttachedSignaturePrefix> {
    let (more, type_c) = take(1u8)(s)?;

    const a: &'static [u8] = "A".as_bytes();
    const b: &'static [u8] = "B".as_bytes();
    const z: &'static [u8] = "0".as_bytes();

    match type_c {
        a => {
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
        b => {
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
        z => {
            let (maybe_count, type_c_2) = take(1u8)(more)?;
            match type_c_2 {
                a => {
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

pub fn basic_prefix(s: &[u8]) -> nom::IResult<&[u8], BasicPrefix> {
    const EXT: &'static [u8] = "1".as_bytes();

    let (_, type_c) = take(1u8)(s)?;

    let (rest, code_str) = take(match type_c {
        EXT => 4u8,
        _ => 1u8,
    })(s)?;

    let code: Basic = String::from_utf8(code_str.to_vec())
        .map_err(|_| nom::Err::Failure((s, ErrorKind::IsNot)))?
        .parse()
        .map_err(|_| nom::Err::Failure((s, ErrorKind::IsNot)))?;

    let (extra, b) = take(code.derivative_b64_len())(rest)?;
    let pk = Key::new(b.to_vec());
    Ok((extra, code.derive(pk)))
}

pub fn self_signing_prefix(s: &[u8]) -> nom::IResult<&[u8], SelfSigningPrefix> {
    const EXT: &'static [u8] = "1".as_bytes();

    let (_, type_c) = take(1u8)(s)?;

    let (rest, code_str) = take(match type_c {
        EXT => 4u8,
        _ => 2u8,
    })(s)?;

    let code: SelfSigning = String::from_utf8(code_str.to_vec())
        .map_err(|_| nom::Err::Failure((s, ErrorKind::IsNot)))?
        .parse()
        .map_err(|_| nom::Err::Failure((s, ErrorKind::IsNot)))?;

    let (extra, b) = take(code.derivative_b64_len())(rest)?;

    Ok((extra, code.derive(b.to_vec())))
}

#[test]
fn test() {
    assert_eq!(
        attached_signature("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes()),
        Ok(("".as_bytes(), AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, vec![0u8; 64], 0)))
    );

    assert_eq!(
        attached_signature("BCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes()),
        Ok(("AA".as_bytes(), AttachedSignaturePrefix::new(SelfSigning::ECDSAsecp256k1Sha256, vec![0u8; 64], 2)))
    );
}
