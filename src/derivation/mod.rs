use core::{
    fmt::{Error, Formatter},
    str::FromStr,
};
use ursa::keys::PublicKey;

// TODO consider how the length info can be encoded in this type, i.e.
// [u8; 32] | [u8; 64]
pub type Derivative = Vec<u8>;

pub enum Derivation {
    // length 1 derivations
    Ed25519PublicKeyNT(fn(key: &PublicKey) -> Derivative),
    X25519PublicKey(fn(key: &PublicKey) -> Derivative),
    Ed25519PublicKey(fn(key: &PublicKey) -> Derivative),
    Blake3_256Digest(fn(input: &[u8]) -> Derivative),
    Blake2B256Digest(fn(input: &[u8]) -> Derivative),
    Blake2S256Digest(fn(input: &[u8]) -> Derivative),
    ECDSAsecp256k1PublicKeyNT(fn(key: &PublicKey) -> Derivative),
    ECDSAsecp256k1PublicKey(fn(key: &PublicKey) -> Derivative),
    SHA3_256Digest(fn(input: &[u8]) -> Derivative),
    SHA2_256Digest(fn(input: &[u8]) -> Derivative),

    // length 2 derivations
    Ed25519Signature(fn(input: &[u8]) -> Derivative),
    ECDSAsecp256k1Signature(fn(input: &[u8]) -> Derivative),
    Blake3_512Digest(fn(input: &[u8]) -> Derivative),
    SHA3_512Digest(fn(input: &[u8]) -> Derivative),
    Blake2B512Digest(fn(input: &[u8]) -> Derivative),
    SHA2_512Digest(fn(input: &[u8]) -> Derivative),
}

impl Derivation {
    pub fn to_str(&self) -> &str {
        match self {
            Self::Ed25519PublicKeyNT(_) => "A",
            Self::X25519PublicKey(_) => "B",
            Self::Ed25519PublicKey(_) => "C",
            Self::Blake3_256Digest(_) => "D",
            Self::Blake2B256Digest(_) => "E",
            Self::Blake2S256Digest(_) => "F",
            Self::ECDSAsecp256k1PublicKeyNT(_) => "G",
            Self::ECDSAsecp256k1PublicKey(_) => "H",
            Self::SHA3_256Digest(_) => "I",
            Self::SHA2_256Digest(_) => "J",
            Self::Ed25519Signature(_) => "0A",
            Self::ECDSAsecp256k1Signature(_) => "0B",
            Self::Blake3_512Digest(_) => "0C",
            Self::SHA3_512Digest(_) => "0D",
            Self::Blake2B512Digest(_) => "0E",
            Self::SHA2_512Digest(_) => "0F",
            _ => "",
        }
    }
}

impl FromStr for Derivation {
    type Err = Error;
    fn from_str(str: &str) -> Result<Self, Self::Err> {
        match str {
            "A" => Ok(Derivation::Ed25519PublicKeyNT(|key| key.0.clone())),
            "B" => Ok(Derivation::X25519PublicKey(|key| key.0.clone())),
            "C" => Ok(Derivation::Ed25519PublicKey(|key| key.0.clone())),
            "D" => Ok(Derivation::Blake3_256Digest(|_input| todo!())),
            "E" => Ok(Derivation::Blake2S256Digest(|_input| todo!())),
            "F" => Ok(Derivation::Blake2B256Digest(|_input| todo!())),
            "G" => Ok(Derivation::ECDSAsecp256k1PublicKeyNT(|key| key.0.clone())),
            "H" => Ok(Derivation::ECDSAsecp256k1PublicKey(|key| key.0.clone())),
            "I" => Ok(Derivation::SHA3_256Digest(|_input| todo!())),
            "J" => Ok(Derivation::SHA2_256Digest(|_input| todo!())),
            "0A" => Ok(Derivation::Ed25519Signature(|_input| todo!())),
            "0B" => Ok(Derivation::ECDSAsecp256k1Signature(|_input| todo!())),
            "0C" => Ok(Derivation::Blake3_512Digest(|_input| todo!())),
            "0D" => Ok(Derivation::SHA3_512Digest(|_input| todo!())),
            "0E" => Ok(Derivation::Blake2B256Digest(|_input| todo!())),
            "0F" => Ok(Derivation::SHA2_512Digest(|_input| todo!())),
            _ => Err(Error),
        }
    }
}

impl std::cmp::PartialEq for Derivation {
    fn eq(&self, other: &Self) -> bool {
        self.to_str() == other.to_str()
    }
}

impl std::fmt::Display for Derivation {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{}", self.to_str())
    }
}
