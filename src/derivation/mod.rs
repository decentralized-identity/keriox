use core::{
    fmt::{Debug, Display, Error, Formatter},
    str::FromStr,
};
use ursa::keys::PublicKey;

// TODO consider how the length info can be encoded in this type, i.e.
// [u8; 32] | [u8; 64]
pub type Derivative = Vec<u8>;

/// Derivation Types
///
/// Derivation represents the enumerated set of derivation procedures defined in section 14 of the paper.
/// Derivations may take varying types of data as input (for now, TODO consider a 'Derivable' trait), but all return a Derivative.
///
/// # Examples
/// ```
/// use crate::keriox::derivation::Derivation;
/// let drv: Derivation = "A".parse().unwrap();
/// ````
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

/// Derivation Codes
///
/// String codes for referencing derivation procedures, as defined in tables 14.2, 14.3 and 14.5
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
        }
    }
}

impl FromStr for Derivation {
    type Err = Error;
    fn from_str(str: &str) -> Result<Self, Self::Err> {
        match str {
            "A" => Ok(Derivation::Ed25519PublicKeyNT(
                procedures::basic::basic_key_derivation,
            )),
            "B" => Ok(Derivation::X25519PublicKey(
                procedures::basic::basic_key_derivation,
            )),
            "C" => Ok(Derivation::Ed25519PublicKey(
                procedures::basic::basic_key_derivation,
            )),
            "D" => Ok(Derivation::Blake3_256Digest(
                procedures::self_addressing::blake3_256_digest,
            )),
            "E" => Ok(Derivation::Blake2S256Digest(
                procedures::self_addressing::blake2s_256_digest,
            )),
            "F" => Ok(Derivation::Blake2B256Digest(
                procedures::self_addressing::blake2b_256_digest,
            )),
            "G" => Ok(Derivation::ECDSAsecp256k1PublicKeyNT(
                procedures::basic::basic_key_derivation,
            )),
            "H" => Ok(Derivation::ECDSAsecp256k1PublicKey(
                procedures::basic::basic_key_derivation,
            )),
            "I" => Ok(Derivation::SHA3_256Digest(
                procedures::self_addressing::sha3_256_digest,
            )),
            "J" => Ok(Derivation::SHA2_256Digest(
                procedures::self_addressing::sha2_256_digest,
            )),
            "0A" => Ok(Derivation::Ed25519Signature(
                procedures::self_signing::self_signing_derivation,
            )),
            "0B" => Ok(Derivation::ECDSAsecp256k1Signature(
                procedures::self_signing::self_signing_derivation,
            )),
            "0C" => Ok(Derivation::Blake3_512Digest(
                procedures::self_addressing::blake3_512_digest,
            )),
            "0D" => Ok(Derivation::SHA3_512Digest(
                procedures::self_addressing::sha3_512_digest,
            )),
            "0E" => Ok(Derivation::Blake2B256Digest(
                procedures::self_addressing::blake2b_512_digest,
            )),
            "0F" => Ok(Derivation::SHA2_512Digest(
                procedures::self_addressing::sha2_512_digest,
            )),
            _ => Err(Error),
        }
    }
}

impl PartialEq for Derivation {
    fn eq(&self, other: &Self) -> bool {
        self.to_str() == other.to_str()
    }
}

impl Display for Derivation {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{}", self.to_str())
    }
}

impl Debug for Derivation {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{}", self.to_str())
    }
}

/// Derivation Procedures Module
pub mod procedures {
    use super::Derivative;

    /// Basic Derivations
    ///
    /// Basic prefix derivation is just a public key (2.3.1)
    ///
    pub mod basic {
        use super::Derivative;
        use ursa::keys::PublicKey;

        pub fn basic_key_derivation(key: &PublicKey) -> Derivative {
            key.0.clone()
        }
    }

    /// Self Signing Derivations
    ///
    /// A self signing prefix derivation outputs a signature as its derivative (2.3.5)
    ///
    pub mod self_signing {
        use super::Derivative;

        pub fn self_signing_derivation(sig: &[u8]) -> Derivative {
            sig.to_vec()
        }
    }

    /// Self Addressing Derivations
    ///
    /// Self-addressing is a digest/hash of some inception data (2.3.2)
    ///   Multi-sig Self-addressing is a self-addressing where the inception data is the public key info of the multisig set (2.3.3)
    ///   Delegated Self-addressing uses the Dip event data for the inception data (2.3.4)
    ///
    pub mod self_addressing {
        use super::Derivative;
        use ursa::hash::{
            blake2::Blake2,
            sha2::{Sha256, Sha512},
            sha3::{Sha3_256, Sha3_512},
            Digest,
        };

        pub fn blake3_256_digest(input: &[u8]) -> Derivative {
            todo!()
        }

        pub fn blake2s_256_digest(input: &[u8]) -> Derivative {
            todo!()
        }

        pub fn blake2b_256_digest(input: &[u8]) -> Derivative {
            Blake2::digest(input).to_vec()
        }

        pub fn blake3_512_digest(input: &[u8]) -> Derivative {
            todo!()
        }

        pub fn blake2b_512_digest(input: &[u8]) -> Derivative {
            todo!()
        }

        pub fn sha3_256_digest(input: &[u8]) -> Derivative {
            let mut h = Sha3_256::new();
            h.input(input);
            h.result().to_vec()
        }

        pub fn sha2_256_digest(input: &[u8]) -> Derivative {
            let mut h = Sha256::new();
            h.input(input);
            h.result().to_vec()
        }

        pub fn sha3_512_digest(input: &[u8]) -> Derivative {
            let mut h = Sha3_512::new();
            h.input(input);
            h.result().to_vec()
        }

        pub fn sha2_512_digest(input: &[u8]) -> Derivative {
            let mut h = Sha512::new();
            h.input(input);
            h.result().to_vec()
        }
    }
}
