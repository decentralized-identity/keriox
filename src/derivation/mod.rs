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
