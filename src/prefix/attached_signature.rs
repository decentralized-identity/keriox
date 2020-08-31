use super::{self_signing::SelfSigningPrefix, Prefix};
use crate::error::Error;
use base64::{decode_config, encode_config};
use core::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, PartialEq, Clone)]
pub struct AttachedSignaturePrefix {
    pub index: u16,
    pub sig: SelfSigningPrefix,
}

impl AttachedSignaturePrefix {
    pub fn new(index: u16, sig: SelfSigningPrefix) -> Self {
        Self { index, sig }
    }
}

impl FromStr for AttachedSignaturePrefix {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match &s[..1] {
            "A" => Self {
                index: b64_to_num(&s[1..2])?,
                sig: SelfSigningPrefix::Ed25519Sha512(decode_config(&s[2..], base64::URL_SAFE)?),
            },
            "B" => Self {
                index: b64_to_num(&s[1..2])?,
                sig: SelfSigningPrefix::ECDSAsecp256k1Sha256(decode_config(
                    &s[2..],
                    base64::URL_SAFE,
                )?),
            },
            "0" => match &s[1..2] {
                "A" => Self {
                    index: b64_to_num(&s[2..4])?,
                    sig: SelfSigningPrefix::Ed448(decode_config(&s[4..], base64::URL_SAFE)?),
                },
                _ => return Err(Error::DeserializationError),
            },
            _ => return Err(Error::DeserializationError),
        })
    }
}

impl Prefix for AttachedSignaturePrefix {
    fn derivative(&self) -> &[u8] {
        &self.sig.derivative()
    }
    // TODO, this will only work with indicies up to 63
    fn derivation_code(&self) -> String {
        [
            match self.sig {
                SelfSigningPrefix::Ed25519Sha512(_) => "A",
                SelfSigningPrefix::ECDSAsecp256k1Sha256(_) => "B",
                SelfSigningPrefix::Ed448(_) => "0AA",
            },
            &num_to_b64(self.index),
        ]
        .join("")
    }
}

pub fn get_sig_count(num: u16) -> String {
    ["-AA", &num_to_b64(num)].join("")
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

/// Serde compatible Serialize
impl Serialize for AttachedSignaturePrefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str())
    }
}

/// Serde compatible Deserialize
impl<'de> Deserialize<'de> for AttachedSignaturePrefix {
    fn deserialize<D>(deserializer: D) -> Result<AttachedSignaturePrefix, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        AttachedSignaturePrefix::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize() -> Result<(), Error> {
        let attached_ed_1 = "AB";
        let attached_secp_2 = "BC";
        let attached_448_3 = "0AAD";

        let pref_ed_1 = AttachedSignaturePrefix::from_str(attached_ed_1)?;
        let pref_secp_2 = AttachedSignaturePrefix::from_str(attached_secp_2)?;
        let pref_448_3 = AttachedSignaturePrefix::from_str(attached_448_3)?;

        assert_eq!(1, pref_ed_1.index);
        assert_eq!(2, pref_secp_2.index);
        assert_eq!(3, pref_448_3.index);

        assert!(match pref_ed_1.sig {
            SelfSigningPrefix::Ed25519Sha512(_) => true,
            _ => false,
        });
        assert!(match pref_secp_2.sig {
            SelfSigningPrefix::ECDSAsecp256k1Sha256(_) => true,
            _ => false,
        });
        assert!(match pref_448_3.sig {
            SelfSigningPrefix::Ed448(_) => true,
            _ => false,
        });
        Ok(())
    }

    #[test]
    fn serialize() -> Result<(), Error> {
        let pref_ed_2 = AttachedSignaturePrefix {
            index: 2,
            sig: SelfSigningPrefix::Ed25519Sha512(vec![0u8; 64]),
        };
        let pref_secp_6 = AttachedSignaturePrefix {
            index: 6,
            sig: SelfSigningPrefix::ECDSAsecp256k1Sha256(vec![0u8; 64]),
        };
        let pref_448_4 = AttachedSignaturePrefix {
            index: 4,
            sig: SelfSigningPrefix::Ed448(vec![0u8; 114]),
        };

        assert_eq!(88, pref_ed_2.to_str().len());
        assert_eq!(88, pref_secp_6.to_str().len());
        assert_eq!(156, pref_448_4.to_str().len());

        assert_eq!("ACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", pref_ed_2.to_str());
        assert_eq!("BGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", pref_secp_6.to_str());
        assert_eq!("0AAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", pref_448_4.to_str());
        Ok(())
    }
}
