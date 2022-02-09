use super::{verify, Prefix, SelfSigningPrefix};
use crate::{
    derivation::{basic::Basic, DerivationCode},
    error::Error,
    keys::PublicKey,
};
use base64::decode_config;
use core::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone)]
pub struct BasicPrefix {
    pub derivation: Basic,
    pub public_key: PublicKey,
}

impl BasicPrefix {
    pub fn new(code: Basic, public_key: PublicKey) -> Self {
        Self {
            derivation: code,
            public_key,
        }
    }

    pub fn verify(&self, data: &[u8], signature: &SelfSigningPrefix) -> Result<bool, Error> {
        verify(data, self, signature)
    }
}

impl PartialEq for BasicPrefix {
    fn eq(&self, other: &Self) -> bool {
        self.derivation == other.derivation && self.public_key == other.public_key
    }
}

impl FromStr for BasicPrefix {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = Basic::from_str(s)?;

        if s.len() == code.prefix_b64_len() {
            let k_vec =
                decode_config(&s[code.code_len()..code.prefix_b64_len()], base64::URL_SAFE)?;
            Ok(Self::new(code, PublicKey::new(k_vec)))
        } else {
            Err(Error::SemanticError(format!(
                "Incorrect Prefix Length: {}",
                s
            )))
        }
    }
}

impl Prefix for BasicPrefix {
    fn derivative(&self) -> Vec<u8> {
        self.public_key.key()
    }
    fn derivation_code(&self) -> String {
        self.derivation.to_str()
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

#[test]
fn serialize_deserialize() {
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;

    let kp = Keypair::generate(&mut OsRng);

    let bp = BasicPrefix {
        derivation: Basic::Ed25519,
        public_key: PublicKey::new(kp.public.to_bytes().to_vec()),
    };

    let serialized = serde_json::to_string(&bp);
    assert!(serialized.is_ok());

    let deserialized = serde_json::from_str(&serialized.unwrap());

    assert!(deserialized.is_ok());
    assert_eq!(bp, deserialized.unwrap());
}

#[test]
fn to_from_string() {
    use crate::keys::PrivateKey;
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;

    let kp = Keypair::generate(&mut OsRng);

    let signer = PrivateKey::new(kp.secret.to_bytes().to_vec());

    let message = b"hello there";
    let sig = SelfSigningPrefix::new(
        crate::derivation::self_signing::SelfSigning::Ed25519Sha512,
        signer.sign_ed(message).unwrap(),
    );

    let bp = BasicPrefix {
        derivation: Basic::Ed25519,
        public_key: PublicKey::new(kp.public.to_bytes().to_vec()),
    };

    assert!(bp.verify(message, &sig).unwrap());

    let string = bp.to_str();

    let from_str = BasicPrefix::from_str(&string);

    assert!(from_str.is_ok());
    let deser = from_str.unwrap();
    assert_eq!(bp, deser);

    assert!(deser.verify(message, &sig).unwrap());
}
