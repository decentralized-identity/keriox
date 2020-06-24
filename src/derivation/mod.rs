use ursa::hash::{
    blake2::Blake2,
    sha2::{Sha256, Sha512},
    sha3::{Sha3_256, Sha3_512},
    Digest,
};
use wasm_bindgen::prelude::*;

/// Basic Derivations
///
/// Basic prefix derivation is just a public key (2.3.1)
///
#[wasm_bindgen]
pub fn basic_key_derivation(key: &[u8]) -> Vec<u8> {
    key.to_vec()
}

/// Self Signing Derivations
///
/// A self signing prefix derivation outputs a signature as its derivative (2.3.5)
///
#[wasm_bindgen]
pub fn self_signing_derivation(sig: &[u8]) -> Vec<u8> {
    sig.to_vec()
}

/// Self Addressing Derivations
///
/// Self-addressing is a digest/hash of some inception data (2.3.2)
///   Multi-sig Self-addressing is a self-addressing where the inception data is the public key info of the multisig set (2.3.3)
///   Delegated Self-addressing uses the Dip event data for the inception data (2.3.4)
///
#[wasm_bindgen]
pub fn blake3_256_digest(_input: &[u8]) -> Vec<u8> {
    todo!()
}

#[wasm_bindgen]
pub fn blake2s_256_digest(_input: &[u8]) -> Vec<u8> {
    todo!()
}

#[wasm_bindgen]
pub fn blake2b_256_digest(input: &[u8]) -> Vec<u8> {
    Blake2::digest(input).to_vec()
}

#[wasm_bindgen]
pub fn blake3_512_digest(_input: &[u8]) -> Vec<u8> {
    todo!()
}

#[wasm_bindgen]
pub fn blake2b_512_digest(_input: &[u8]) -> Vec<u8> {
    todo!()
}

#[wasm_bindgen]
pub fn sha3_256_digest(input: &[u8]) -> Vec<u8> {
    let mut h = Sha3_256::new();
    h.input(input);
    h.result().to_vec()
}

#[wasm_bindgen]
pub fn sha2_256_digest(input: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.input(input);
    h.result().to_vec()
}

#[wasm_bindgen]
pub fn sha3_512_digest(input: &[u8]) -> Vec<u8> {
    let mut h = Sha3_512::new();
    h.input(input);
    h.result().to_vec()
}

#[wasm_bindgen]
pub fn sha2_512_digest(input: &[u8]) -> Vec<u8> {
    let mut h = Sha512::new();
    h.input(input);
    h.result().to_vec()
}
