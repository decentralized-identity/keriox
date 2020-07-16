use crate::error::Error;
use base64::{decode_config, encode_config};
use core::{
    fmt::{Display, Formatter},
    str::FromStr,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ursa::{
    keys::PublicKey,
    signatures::{ed25519::Ed25519Sha512, secp256k1::EcdsaSecp256k1Sha256, SignatureScheme},
};

#[derive(Debug, PartialEq, Clone)]
pub enum Prefix {
    PubKeyEd25519NT(PublicKey),
    PubKeyX25519(PublicKey),
    PubKeyEd25519(PublicKey),
    PubKeyECDSAsecp256k1NT(PublicKey),
    PubKeyECDSAsecp256k1(PublicKey),
    SigEd25519Sha512(Vec<u8>),
    SigECDSAsecp256k1Sha256(Vec<u8>),
    Blake3_256(Vec<u8>),
    Blake2B256(Vec<u8>),
    Blake2S256(Vec<u8>),
    SHA3_256(Vec<u8>),
    SHA2_256(Vec<u8>),
    Blake3_512(Vec<u8>),
    SHA3_512(Vec<u8>),
    Blake2B512(Vec<u8>),
    SHA2_512(Vec<u8>),
}

impl Prefix {
    pub fn derivative(&self) -> &[u8] {
        match self {
            Self::PubKeyEd25519NT(p) => &p.0,
            Self::PubKeyX25519(p) => &p.0,
            Self::PubKeyEd25519(p) => &p.0,
            Self::PubKeyECDSAsecp256k1NT(p) => &p.0,
            Self::PubKeyECDSAsecp256k1(p) => &p.0,

            Self::SigEd25519Sha512(s) => &s,
            Self::SigECDSAsecp256k1Sha256(s) => &s,
            Self::Blake3_256(d) => &d,
            Self::Blake2B256(d) => &d,
            Self::Blake2S256(d) => &d,
            Self::SHA3_256(d) => &d,
            Self::SHA2_256(d) => &d,
            Self::Blake3_512(d) => &d,
            Self::SHA3_512(d) => &d,
            Self::Blake2B512(d) => &d,
            Self::SHA2_512(d) => &d,
        }
    }

    pub fn derivation_code(&self) -> &str {
        match self {
            Self::PubKeyEd25519NT(_) => "A",
            Self::PubKeyX25519(_) => "B",
            Self::PubKeyEd25519(_) => "C",
            Self::PubKeyECDSAsecp256k1NT(_) => "G",
            Self::PubKeyECDSAsecp256k1(_) => "H",

            Self::SigEd25519Sha512(_) => "0A",
            Self::SigECDSAsecp256k1Sha256(_) => "0B",

            Self::Blake3_256(_) => "D",
            Self::Blake2B256(_) => "E",
            Self::Blake2S256(_) => "F",
            Self::SHA3_256(_) => "I",
            Self::SHA2_256(_) => "J",
            Self::Blake3_512(_) => "0C",
            Self::SHA3_512(_) => "0D",
            Self::Blake2B512(_) => "0E",
            Self::SHA2_512(_) => "0F",
        }
    }

    pub fn to_str(&self) -> String {
        let encoded = encode_config(self.derivative(), base64::URL_SAFE);
        [
            self.derivation_code(),
            &encoded[..encoded.len() - self.derivation_code().len()],
        ]
        .join("")
    }

    pub fn verify(&self, data: &Prefix, signature: &Prefix) -> Result<bool, Error> {
        verify(data, self, signature)
    }
}

// TODO currently this assumes signatures being made over the data prefix. URSA actually hashes the
// message itself (sha512 for secp256k1, sha256 for ed25519), so verification (if we take this in to account)
// will require the vanilla message
pub fn verify(data: &Prefix, key: &Prefix, signature: &Prefix) -> Result<bool, Error> {
    match key {
        Prefix::PubKeyEd25519(pk) | Prefix::PubKeyEd25519NT(pk) => match signature {
            Prefix::SigEd25519Sha512(sig) => {
                let ed = Ed25519Sha512::new();
                ed.verify(data.to_str().as_bytes(), sig, &pk)
                    .map_err(|e| Error::CryptoError(e))
            }
            _ => Err(Error::SemanticError("wrong sig type".to_string())),
        },
        Prefix::PubKeyECDSAsecp256k1(pk) | Prefix::PubKeyECDSAsecp256k1NT(pk) => match signature {
            Prefix::SigECDSAsecp256k1Sha256(sig) => {
                let secp = EcdsaSecp256k1Sha256::new();
                secp.verify(data.to_str().as_bytes(), sig, &pk)
                    .map_err(|e| Error::CryptoError(e))
            }
            _ => Err(Error::SemanticError("wrong sig type".to_string())),
        },
        _ => Err(Error::SemanticError("inelligable key type".to_string())),
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
        match &str[..1] {
            // length 1 derivation codes
            "A" => Ok(Self::PubKeyEd25519NT(PublicKey(decode_derivative(
                &str[1..],
            )?))),
            "B" => Ok(Self::PubKeyX25519(PublicKey(decode_derivative(&str[1..])?))),
            "C" => Ok(Self::PubKeyEd25519(PublicKey(decode_derivative(
                &str[1..],
            )?))),
            "D" => Ok(Self::Blake3_256(decode_derivative(&str[1..])?)),
            "E" => Ok(Self::Blake2B256(decode_derivative(&str[1..])?)),
            "F" => Ok(Self::Blake2S256(decode_derivative(&str[1..])?)),
            "G" => Ok(Self::PubKeyECDSAsecp256k1NT(PublicKey(decode_derivative(
                &str[1..],
            )?))),
            "H" => Ok(Self::PubKeyECDSAsecp256k1(PublicKey(decode_derivative(
                &str[1..],
            )?))),
            "I" => Ok(Self::SHA3_256(decode_derivative(&str[1..])?)),
            "J" => Ok(Self::SHA2_256(decode_derivative(&str[1..])?)),
            // length 2 derivation codes
            "0" => match &str[1..2] {
                "A" => Ok(Self::SigEd25519Sha512(decode_derivative(&str[2..])?)),
                "B" => Ok(Self::SigECDSAsecp256k1Sha256(decode_derivative(&str[2..])?)),
                "C" => Ok(Self::Blake3_512(decode_derivative(&str[2..])?)),
                "D" => Ok(Self::SHA3_512(decode_derivative(&str[2..])?)),
                "E" => Ok(Self::Blake2B512(decode_derivative(&str[2..])?)),
                "F" => Ok(Self::SHA2_512(decode_derivative(&str[2..])?)),
                _ => Err(Error::DeserializationError(core::fmt::Error)),
            },
            // no derivation codes longer than 2 chars yet
            _ => Err(Error::DeserializationError(core::fmt::Error)),
        }
    }
}

fn decode_derivative(str: &str) -> Result<Vec<u8>, Error> {
    decode_config(str, base64::URL_SAFE).map_err(|_| Error::DeserializationError(core::fmt::Error))
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

/// Serde compatible Deserialize
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

impl Default for Prefix {
    fn default() -> Self {
        Self::SHA3_512(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derivation;
    use ursa::{keys, signatures};

    #[test]
    fn simple_deserialize() -> Result<(), Error> {
        let pref: Prefix = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse()?;

        assert_eq!(pref.derivation_code(), "A");

        assert_eq!(pref.derivative().len(), 32);

        assert_eq!(pref.derivative().to_vec(), vec![0u8; 32]);

        Ok(())
    }

    #[test]
    fn simple_serialize() -> Result<(), Error> {
        let pref = Prefix::PubKeyEd25519NT(keys::PublicKey(vec![0; 32]));

        assert_eq!(
            pref.to_str(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );

        Ok(())
    }

    #[test]
    fn verify() -> Result<(), Error> {
        let data_string = "hello there";
        let data_prefix = Prefix::SHA3_256(derivation::sha3_256_digest(data_string.as_bytes()));

        let ed = signatures::ed25519::Ed25519Sha512::new();

        let (pub_key, priv_key) = ed
            .keypair(Some(keys::KeyGenOption::UseSeed(vec![0u8; 32])))
            .map_err(|e| Error::CryptoError(e))?;

        let key_prefix = Prefix::PubKeyEd25519NT(pub_key);

        let sig = ed
            .sign(&data_prefix.to_str().as_bytes(), &priv_key)
            .map_err(|e| Error::CryptoError(e))?;

        let sig_prefix = Prefix::SigEd25519Sha512(sig);

        assert!(true, key_prefix.verify(&data_prefix, &sig_prefix)?);

        Ok(())
    }
}
