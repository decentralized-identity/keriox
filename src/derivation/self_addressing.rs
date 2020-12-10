use super::DerivationCode;
use crate::{error::Error, prefix::SelfAddressingPrefix};
use blake3;
use core::str::FromStr;
use ursa::hash::{
    blake2::Blake2,
    sha2::{Sha256, Sha512},
    sha3::{Sha3_256, Sha3_512},
    Digest,
};

/// Self Addressing Derivations
///
/// Self-addressing is a digest/hash of some inception data (2.3.2)
///   Delegated Self-addressing uses the Dip event data for the inception data (2.3.4)
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum SelfAddressing {
    Blake3_256,
    Blake2B256,
    Blake2S256,
    SHA3_256,
    SHA2_256,
    Blake3_512,
    SHA3_512,
    Blake2B512,
    SHA2_512,
}

impl SelfAddressing {
    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Blake3_256 => blake3_256_digest(data),
            Self::Blake2B256 => blake2b_256_digest(data),
            Self::Blake2S256 => blake2s_256_digest(data),
            Self::SHA3_256 => sha3_256_digest(data),
            Self::SHA2_256 => sha2_256_digest(data),
            Self::Blake3_512 => blake3_512_digest(data),
            Self::SHA3_512 => sha3_512_digest(data),
            Self::Blake2B512 => blake2b_512_digest(data),
            Self::SHA2_512 => sha2_512_digest(data),
        }
    }

    pub fn derive(&self, data: &[u8]) -> SelfAddressingPrefix {
        SelfAddressingPrefix::new(*self, self.digest(data))
    }
}

impl DerivationCode for SelfAddressing {
    fn to_str(&self) -> String {
        match self {
            Self::Blake3_256 => "E",
            Self::Blake2B256 => "F",
            Self::Blake2S256 => "G",
            Self::SHA3_256 => "H",
            Self::SHA2_256 => "I",
            Self::Blake3_512 => "0D",
            Self::SHA3_512 => "0E",
            Self::Blake2B512 => "0F",
            Self::SHA2_512 => "0G",
        }
        .into()
    }

    fn code_len(&self) -> usize {
        match self {
            Self::Blake3_256
            | Self::Blake2B256
            | Self::Blake2S256
            | Self::SHA3_256
            | Self::SHA2_256 => 1,
            Self::Blake3_512 | Self::SHA3_512 | Self::Blake2B512 | Self::SHA2_512 => 2,
        }
    }

    fn derivative_b64_len(&self) -> usize {
        match self {
            Self::Blake3_256
            | Self::Blake2B256
            | Self::Blake2S256
            | Self::SHA3_256
            | Self::SHA2_256 => 43,
            Self::Blake3_512 | Self::SHA3_512 | Self::Blake2B512 | Self::SHA2_512 => 86,
        }
    }
}

impl FromStr for SelfAddressing {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[..1] {
            "E" => Ok(Self::Blake3_256),
            "F" => Ok(Self::Blake2B256),
            "G" => Ok(Self::Blake2S256),
            "H" => Ok(Self::SHA3_256),
            "I" => Ok(Self::SHA2_256),
            "0" => match &s[1..2] {
                "D" => Ok(Self::Blake3_512),
                "E" => Ok(Self::SHA3_512),
                "F" => Ok(Self::Blake2B512),
                "G" => Ok(Self::SHA2_512),
                _ => Err(Error::DeserializationError),
            },
            _ => Err(Error::DeserializationError),
        }
    }
}

fn blake3_256_digest(input: &[u8]) -> Vec<u8> {
    blake3::hash(input).as_bytes().to_vec()
}

fn blake2s_256_digest(_input: &[u8]) -> Vec<u8> {
    todo!()
}

// TODO it seems that blake2b is always defined as outputting 512 bits?
fn blake2b_256_digest(_input: &[u8]) -> Vec<u8> {
    todo!()
}

fn blake3_512_digest(input: &[u8]) -> Vec<u8> {
    let mut out = [0u8; 64];
    let mut h = blake3::Hasher::new();
    h.update(input);
    h.finalize_xof().fill(&mut out);
    out.to_vec()
}

fn blake2b_512_digest(input: &[u8]) -> Vec<u8> {
    Blake2::digest(input).to_vec()
}

fn sha3_256_digest(input: &[u8]) -> Vec<u8> {
    let mut h = Sha3_256::new();
    h.input(input);
    h.result().to_vec()
}

fn sha2_256_digest(input: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.input(input);
    h.result().to_vec()
}

fn sha3_512_digest(input: &[u8]) -> Vec<u8> {
    let mut h = Sha3_512::new();
    h.input(input);
    h.result().to_vec()
}

fn sha2_512_digest(input: &[u8]) -> Vec<u8> {
    let mut h = Sha512::new();
    h.input(input);
    h.result().to_vec()
}
