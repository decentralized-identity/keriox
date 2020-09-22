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
            "A" => Ok(Self::new(SelfSigning::Ed25519Sha512, b64_to_num(&s[1..2])?)),
            "B" => Ok(Self::new(
                SelfSigning::ECDSAsecp256k1Sha256,
                b64_to_num(&s[1..2])?,
            )),
            "0" => match &s[1..3] {
                "AA" => Ok(Self::new(SelfSigning::Ed448, b64_to_num(&s[3..4])?)),
                _ => Err(Error::DeserializationError),
            },
            _ => Err(Error::DeserializationError),
        }
    }
}

// returns the u16 from the lowest 2 bytes of the b64 string
// currently only works for strings 4 chars or less
pub fn b64_to_num(b64: &str) -> Result<u16, Error> {
    let slice = decode_config(
        match b64.len() {
            1 => ["AAA", b64].join(""),
            2 => ["AA", b64].join(""),
            _ => b64.to_string(),
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
            encode_config(&[num.to_be_bytes()[1] << 2], base64::URL_SAFE)[..1].to_string()
        }
        n if n < 4095 => encode_config(num.to_be_bytes(), base64::URL_SAFE)[..2].to_string(),
        _ => encode_config(num.to_be_bytes(), base64::URL_SAFE),
    }
}

pub fn get_sig_count(num: u16) -> String {
    ["-AA", &num_to_b64(num)].join("")
}
