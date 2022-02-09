use super::{self_signing::SelfSigning, DerivationCode};
use crate::error::Error;
use base64::{decode_config, encode_config};
use core::str::FromStr;

/// Attached Signature Derivation Codes
///
/// A self signing prefix derivation outputs a signature as its derivative (2.3.5)
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct AttachedSignatureCode {
    pub index: u16,
    pub code: SelfSigning,
}

impl AttachedSignatureCode {
    pub fn new(code: SelfSigning, index: u16) -> Self {
        Self { index, code }
    }
}

impl DerivationCode for AttachedSignatureCode {
    // TODO, this will only work with indicies up to 63
    fn to_str(&self) -> String {
        [
            match self.code {
                SelfSigning::Ed25519Sha512 => "A",
                SelfSigning::ECDSAsecp256k1Sha256 => "B",
                SelfSigning::Ed448 => "0AA",
            },
            &num_to_b64(self.index),
        ]
        .join("")
    }

    fn code_len(&self) -> usize {
        match self.code {
            SelfSigning::Ed25519Sha512 | SelfSigning::ECDSAsecp256k1Sha256 => 2,
            SelfSigning::Ed448 => 4,
        }
    }

    fn derivative_b64_len(&self) -> usize {
        match self.code {
            SelfSigning::Ed25519Sha512 | SelfSigning::ECDSAsecp256k1Sha256 => 86,
            SelfSigning::Ed448 => 152,
        }
    }
}

impl FromStr for AttachedSignatureCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[..1] {
            "A" => Ok(Self::new(
                SelfSigning::Ed25519Sha512,
                b64_to_num(&s.as_bytes()[1..2])?,
            )),
            "B" => Ok(Self::new(
                SelfSigning::ECDSAsecp256k1Sha256,
                b64_to_num(&s.as_bytes()[1..2])?,
            )),
            "0" => match &s[1..3] {
                "AA" => Ok(Self::new(
                    SelfSigning::Ed448,
                    b64_to_num(&s.as_bytes()[3..4])?,
                )),
                _ => Err(Error::DeserializeError("Unknows signature code".into())),
            },
            _ => Err(Error::DeserializeError("Unknown attachment code".into())),
        }
    }
}

// returns the u16 from the lowest 2 bytes of the b64 string
// currently only works for strings 4 chars or less
pub fn b64_to_num(b64: &[u8]) -> Result<u16, Error> {
    let slice = decode_config(
        match b64.len() {
            1 => [r"AAA".as_bytes(), b64].concat(),
            2 => [r"AA".as_bytes(), b64].concat(),
            _ => b64.to_owned(),
        },
        base64::URL_SAFE,
    )
    .map_err(|e| Error::Base64DecodingError { source: e })?;
    let len = slice.len();

    Ok(u16::from_be_bytes(match len {
        0 => [0u8; 2],
        1 => [0, slice[0]],
        _ => [slice[len - 2], slice[len - 1]],
    }))
}

pub fn num_to_b64(num: u16) -> String {
    match num {
        n if n < 63 => {
            encode_config([num.to_be_bytes()[1] << 2], base64::URL_SAFE_NO_PAD)[..1].to_string()
        }
        n if n < 4095 => encode_config(num.to_be_bytes(), base64::URL_SAFE_NO_PAD)[..2].to_string(),
        _ => encode_config(num.to_be_bytes(), base64::URL_SAFE_NO_PAD),
    }
}

#[test]
fn num_to_b64_test() {
    assert_eq!("A", num_to_b64(0));
    assert_eq!("B", num_to_b64(1));
    assert_eq!("C", num_to_b64(2));
    assert_eq!("D", num_to_b64(3));
    assert_eq!("b", num_to_b64(27));
    assert_eq!("AE", num_to_b64(64));
}
