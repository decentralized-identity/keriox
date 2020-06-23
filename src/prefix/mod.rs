use crate::{
    derivation::{
        basic::PublicKeyDerivations, self_signing::SelfSigningDerivations, Derivation, Derivative,
        SignatureSchemes,
    },
    error::Error,
};
use ursa::{keys::PublicKey, signatures::SignatureScheme};

pub mod p2;
use base64::{decode_config, encode_config};
use core::{
    fmt::{Display, Formatter},
    str::FromStr,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Prefix
///
/// A Prefix provides a piece of qualified cryptographic material.
/// This is the raw material and a code describing how it was generated.
#[derive(Debug, PartialEq, Clone, Default)]
pub struct Prefix {
    pub derivation_code: Derivation,
    pub derivative: Derivative,
}

impl Prefix {
    pub fn to_str(&self) -> String {
        let encoded_derivative = encode_config(&self.derivative, base64::URL_SAFE);
        let padding = get_prefix_length(&encoded_derivative);
        [
            self.derivation_code.to_str(),
            &encoded_derivative[..encoded_derivative.len() - padding],
        ]
        .join("")
    }

    /// verify
    ///
    /// casts the prefix to a key and uses it to verify a signature against some data
    pub fn verify(&self, data: &Prefix, signature: &Prefix) -> Result<bool, Error> {
        verify(data, signature, self)
    }
}

impl Display for Prefix {
    fn fmt(&self, f: &mut Formatter) -> Result<(), core::fmt::Error> {
        write!(f, "{}", self.to_str())
    }
}

impl FromStr for Prefix {
    type Err = Error;

    // TODO enforce derivative length assumptions for each derivation procedure
    fn from_str(str: &str) -> Result<Self, Self::Err> {
        match parse_padded(str) {
            Ok((drv, padding_length)) => Ok(Prefix {
                derivation_code: drv,
                derivative: decode_config(&str[padding_length..], base64::URL_SAFE)
                    .map_err(|_| Error::DeserializationError(core::fmt::Error))?,
            }),
            Err(e) => Err(e),
        }
    }
}

/// Serde compatible Serialize
impl Serialize for Prefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str())
    }
}

/// Serde compatible Deerialize
impl<'de> Deserialize<'de> for Prefix {
    fn deserialize<D>(deserializer: D) -> Result<Prefix, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        // TODO change from .unwrap()
        let prefix = Prefix::from_str(&s).unwrap();
        Ok(prefix)
    }
}

// TODO currently this assumes signatures being made over the data prefix. URSA actually hashes the
// message itself (sha512 for secp256k1, sha256 for ed25519), so verification (if we take this in to account)
// will require the vanilla message
pub fn verify(data: &Prefix, signature: &Prefix, key: &Prefix) -> Result<bool, Error> {
    match data.derivation_code {
        // ensure data is a digest
        Derivation::Digest(d) => {
            // ensure sig is a signature
            let scheme = get_signing_scheme(key, signature)?;
            match scheme {
                SignatureSchemes::Ed25519Sha512(s) => s
                    .verify(
                        data.to_str().as_bytes(),
                        &signature.derivative,
                        &PublicKey(key.derivative.clone()),
                    )
                    .map_err(|e| Error::CryptoError(e)),
                SignatureSchemes::ECDSAsecp256k1Sha256(s) => s
                    .verify(
                        data.to_str().as_bytes(),
                        &signature.derivative,
                        &PublicKey(key.derivative.clone()),
                    )
                    .map_err(|e| Error::CryptoError(e)),
            }
        }
        _ => Err(Error::SemanticError(
            "incorrect prefix type for Data".to_string(),
        )),
    }
}

fn get_signing_scheme(key: &Prefix, signature: &Prefix) -> Result<SignatureSchemes, Error> {
    match key.derivation_code {
        Derivation::PublicKey(pk) => match signature.derivation_code {
            Derivation::Signature(sig) => match pk {
                PublicKeyDerivations::ECDSAsecp256k1 | PublicKeyDerivations::ECDSAsecp256k1NT => {
                    match sig {
                        SelfSigningDerivations::ECDSAsecp256k1Sha256 => Ok(pk.to_scheme()),
                        _ => Err(Error::SemanticError("wrong sig type".to_string())),
                    }
                }
                PublicKeyDerivations::Ed25519
                | PublicKeyDerivations::Ed25519NT
                | PublicKeyDerivations::X25519 => match sig {
                    SelfSigningDerivations::Ed25519Sha512 => Ok(pk.to_scheme()),
                    _ => Err(Error::SemanticError("wrong sig type".to_string())),
                },
            },
            _ => Err(Error::SemanticError("wrong sig type".to_string())),
        },
        _ => Err(Error::SemanticError("wrong key type".to_string())),
    }
}

fn parse_padded(padded_code: &str) -> Result<(Derivation, usize), Error> {
    match &padded_code[..1] {
        "0" => Ok((Derivation::from_str(&padded_code[..2])?, 2)),
        "1" => Ok((Derivation::from_str(&padded_code[..3])?, 3)),
        "2" => Ok((Derivation::from_str(&padded_code[..4])?, 4)),
        _ => Ok((Derivation::from_str(&padded_code[..1])?, 1)),
    }
}

/// Counts the number of padding bytes (=) in a base64 encoded string,
/// based on which returns the size we should use for the prefix bytes.
/// Section 14. Derivation Codes.

pub fn get_prefix_length(value: &str) -> usize {
    return value.matches('=').count();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derivation;
    use ursa::{keys, signatures};

    #[test]
    fn simple_deserialize() -> Result<(), Error> {
        let pref: Prefix = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse()?;

        assert_eq!(pref.derivation_code, Derivation::from_str("A")?);

        assert_eq!(pref.derivative.len(), 32);

        assert_eq!(pref.derivative, vec![0u8; 32]);

        Ok(())
    }

    #[test]
    fn simple_serialize() -> Result<(), Error> {
        let pref = Prefix {
            derivation_code: Derivation::from_str("A")?,
            derivative: vec![0u8; 32],
        };

        assert_eq!(
            pref.to_str(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );

        Ok(())
    }

    #[test]
    fn verify() -> Result<(), Error> {
        let data_string = "hello there";
        let data_prefix = Prefix {
            derivative: derivation::procedures::self_addressing::sha3_256_digest(
                data_string.as_bytes(),
            ),
            derivation_code: derivation::Derivation::default(),
        };

        let ed = signatures::ed25519::Ed25519Sha512::new();

        let (pub_key, priv_key) = ed
            .keypair(Some(keys::KeyGenOption::UseSeed(vec![0u8; 32])))
            .map_err(|e| Error::CryptoError(e))?;

        let key_prefix = Prefix {
            derivative: pub_key.0.clone(),
            derivation_code: derivation::Derivation::PublicKey(PublicKeyDerivations::Ed25519NT),
        };

        let sig = ed
            .sign(&data_prefix.to_str().as_bytes(), &priv_key)
            .map_err(|e| Error::CryptoError(e))?;

        let sig_prefix = Prefix {
            derivative: sig,
            derivation_code: derivation::Derivation::Signature(
                SelfSigningDerivations::Ed25519Sha512,
            ),
        };

        assert!(true, key_prefix.verify(&data_prefix, &sig_prefix)?);

        Ok(())
    }
}
