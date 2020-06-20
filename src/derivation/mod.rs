use core::{
    fmt::{Debug, Display, Error, Formatter},
    str::FromStr,
};

pub mod basic;
pub mod self_addressing;
pub mod self_signing;

use basic::PublicKeyDerivations;
use self_addressing::SelfAddressingDerivations;
use self_signing::SelfSigningDerivations;

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
    PublicKey(PublicKeyDerivations),
    Digest(SelfAddressingDerivations),
    Signature(SelfSigningDerivations),
}

/// Derivation Codes
///
/// String codes for referencing derivation procedures, as defined in tables 14.2, 14.3 and 14.5
impl Derivation {
    pub fn to_str(&self) -> &str {
        match self {
            Self::PublicKey(p) => p.to_str(),
            Self::Digest(d) => d.to_str(),
            Self::Signature(s) => s.to_str(),
        }
    }
}

impl FromStr for Derivation {
    type Err = Error;
    // TODO use combinators to make this neater
    fn from_str(str: &str) -> Result<Self, Self::Err> {
        match PublicKeyDerivations::from_str(str) {
            Ok(pub_key) => Ok(Derivation::PublicKey(pub_key)),
            Err(_) => match SelfAddressingDerivations::from_str(str) {
                Ok(digest) => Ok(Derivation::Digest(digest)),
                Err(_) => match SelfSigningDerivations::from_str(str) {
                    Ok(sig) => Ok(Derivation::Signature(sig)),
                    Err(e) => Err(e),
                },
            },
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
        use wasm_bindgen::prelude::*;

        #[wasm_bindgen]
        pub fn basic_key_derivation(key: &[u8]) -> Derivative {
            key.to_vec()
        }
    }

    /// Self Signing Derivations
    ///
    /// A self signing prefix derivation outputs a signature as its derivative (2.3.5)
    ///
    pub mod self_signing {
        use super::Derivative;
        use wasm_bindgen::prelude::*;

        #[wasm_bindgen]
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
        use wasm_bindgen::prelude::*;

        #[wasm_bindgen]
        pub fn blake3_256_digest(input: &[u8]) -> Derivative {
            todo!()
        }

        #[wasm_bindgen]
        pub fn blake2s_256_digest(input: &[u8]) -> Derivative {
            todo!()
        }

        #[wasm_bindgen]
        pub fn blake2b_256_digest(input: &[u8]) -> Derivative {
            Blake2::digest(input).to_vec()
        }

        #[wasm_bindgen]
        pub fn blake3_512_digest(input: &[u8]) -> Derivative {
            todo!()
        }

        #[wasm_bindgen]
        pub fn blake2b_512_digest(input: &[u8]) -> Derivative {
            todo!()
        }

        #[wasm_bindgen]
        pub fn sha3_256_digest(input: &[u8]) -> Derivative {
            let mut h = Sha3_256::new();
            h.input(input);
            h.result().to_vec()
        }

        #[wasm_bindgen]
        pub fn sha2_256_digest(input: &[u8]) -> Derivative {
            let mut h = Sha256::new();
            h.input(input);
            h.result().to_vec()
        }

        #[wasm_bindgen]
        pub fn sha3_512_digest(input: &[u8]) -> Derivative {
            let mut h = Sha3_512::new();
            h.input(input);
            h.result().to_vec()
        }

        #[wasm_bindgen]
        pub fn sha2_512_digest(input: &[u8]) -> Derivative {
            let mut h = Sha512::new();
            h.input(input);
            h.result().to_vec()
        }
    }
}
