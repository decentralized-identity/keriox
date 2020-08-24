use super::{verify, Prefix, SelfSigningPrefix};
use crate::error::Error;
use base64::decode_config;
use core::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ursa::keys::PublicKey;

#[derive(Debug, PartialEq, Clone)]
pub enum BasicPrefix {
    ECDSAsecp256k1NT(PublicKey),
    ECDSAsecp256k1(PublicKey),
    Ed25519NT(PublicKey),
    Ed25519(PublicKey),
    Ed448NT(PublicKey),
    Ed448(PublicKey),
    X25519(PublicKey),
    X448(PublicKey),
}

impl BasicPrefix {
    pub fn verify(&self, data: &[u8], signature: &SelfSigningPrefix) -> Result<bool, Error> {
        verify(data, self, signature)
    }
}

impl FromStr for BasicPrefix {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[..1] {
            "B" => Ok(Self::Ed25519NT(PublicKey(decode_config(
                &s[1..],
                base64::URL_SAFE,
            )?))),
            "C" => Ok(Self::X25519(PublicKey(decode_config(
                &s[1..],
                base64::URL_SAFE,
            )?))),
            "D" => Ok(Self::Ed25519(PublicKey(decode_config(
                &s[1..],
                base64::URL_SAFE,
            )?))),
            "L" => Ok(Self::X448(PublicKey(decode_config(
                &s[1..],
                base64::URL_SAFE,
            )?))),
            "1" => match &s[1..4] {
                "AAA" => Ok(Self::ECDSAsecp256k1NT(PublicKey(decode_config(
                    &s[4..],
                    base64::URL_SAFE,
                )?))),
                "AAB" => Ok(Self::ECDSAsecp256k1(PublicKey(decode_config(
                    &s[4..],
                    base64::URL_SAFE,
                )?))),
                "AAC" => Ok(Self::Ed448NT(PublicKey(decode_config(
                    &s[4..],
                    base64::URL_SAFE,
                )?))),
                "AAD" => Ok(Self::Ed448(PublicKey(decode_config(
                    &s[4..],
                    base64::URL_SAFE,
                )?))),
                _ => Err(Error::DeserializationError),
            },
            _ => Err(Error::DeserializationError),
        }
    }
}

impl Prefix for BasicPrefix {
    fn derivative(&self) -> &[u8] {
        match self {
            Self::ECDSAsecp256k1NT(pk) => &pk.0,
            Self::ECDSAsecp256k1(pk) => &pk.0,
            Self::Ed25519NT(pk) => &pk.0,
            Self::Ed25519(pk) => &pk.0,
            Self::Ed448NT(pk) => &pk.0,
            Self::Ed448(pk) => &pk.0,
            Self::X25519(pk) => &pk.0,
            Self::X448(pk) => &pk.0,
        }
    }
    fn derivation_code(&self) -> String {
        match self {
            Self::ECDSAsecp256k1NT(_) => "1AAA".to_string(),
            Self::ECDSAsecp256k1(_) => "1AAB".to_string(),
            Self::Ed448NT(_) => "1AAC".to_string(),
            Self::Ed448(_) => "1AAD".to_string(),
            Self::Ed25519NT(_) => "B".to_string(),
            Self::X25519(_) => "C".to_string(),
            Self::Ed25519(_) => "D".to_string(),
            Self::X448(_) => "L".to_string(),
        }
    }
}

/// Serde compatible Serialize
impl Serialize for BasicPrefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str())
    }
}

/// Serde compatible Deserialize
impl<'de> Deserialize<'de> for BasicPrefix {
    fn deserialize<D>(deserializer: D) -> Result<BasicPrefix, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        BasicPrefix::from_str(&s).map_err(serde::de::Error::custom)
    }
}
