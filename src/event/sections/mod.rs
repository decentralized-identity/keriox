use crate::{
    derivation::self_addressing::SelfAddressing,
    error::Error,
    prefix::{AttachedSignaturePrefix, BasicPrefix, Prefix, SelfAddressingPrefix},
};
use serde::{Deserialize, Serialize};
use serde_hex::{Compact, SerHex};

pub mod seal;

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct KeyConfig {
    #[serde(rename = "kt", with = "SerHex::<Compact>")]
    pub threshold: u64,

    #[serde(rename = "k")]
    pub public_keys: Vec<BasicPrefix>,

    #[serde(rename = "n", with = "empty_string_as_none")]
    pub threshold_key_digest: Option<SelfAddressingPrefix>,
}

impl KeyConfig {
    pub fn new(
        public_keys: Vec<BasicPrefix>,
        threshold_key_digest: Option<SelfAddressingPrefix>,
        threshold: Option<u64>,
    ) -> Self {
        Self {
            threshold: threshold.map_or_else(|| public_keys.len() as u64 / 2 + 1, |t| t),
            public_keys,
            threshold_key_digest,
        }
    }

    /// Verify
    ///
    /// Verifies the given sigs against the given message using the KeyConfigs
    /// Public Keys, according to the indexes in the sigs.
    pub fn verify(&self, message: &[u8], sigs: &[AttachedSignaturePrefix]) -> Result<bool, Error> {
        // ensure there's enough sigs
        if (sigs.len() as u64) < self.threshold {
            Err(Error::NotEnoughSigsError)
        } else if
        // and that there are not too many
        sigs.len() <= self.public_keys.len()
            // and that there are no duplicates
            && sigs
                .iter()
                .fold(vec![0u64; self.public_keys.len()], |mut acc, sig| {
                    acc[sig.index as usize] += 1;
                    acc
                })
                .iter()
                .all(|n| *n <= 1)
        {
            Ok(sigs
                .iter()
                .fold(Ok(true), |acc: Result<bool, Error>, sig| {
                    Ok(acc?
                        && self
                            .public_keys
                            .get(sig.index as usize)
                            .ok_or(Error::SemanticError("Key index not present in set".into()))
                            .and_then(|key: &BasicPrefix| key.verify(message, &sig.signature))?)
                })?)
        } else {
            Err(Error::SemanticError("Invalid signatures set".into()))
        }
    }

    /// Verify Next
    ///
    /// Verifies that the given next KeyConfig matches that which is committed
    /// to in the threshold_key_digest of this KeyConfig
    pub fn verify_next(&self, next: &KeyConfig) -> bool {
        match &self.threshold_key_digest {
            Some(n) => n == &next.commit(&n.derivation),
            None => false,
        }
    }

    /// Serialize For Next
    ///
    /// Serializes the KeyConfig for creation or verification of a threshold
    /// key digest commitment
    pub fn commit(&self, derivation: &SelfAddressing) -> SelfAddressingPrefix {
        nxt_commitment(self.threshold, &self.public_keys, derivation)
    }
}

/// Serialize For Commitment
///
/// Serializes a threshold and key set into the form
/// required for threshold key digest creation
pub fn nxt_commitment(
    threshold: u64,
    keys: &[BasicPrefix],
    derivation: &SelfAddressing,
) -> SelfAddressingPrefix {
    keys.iter().fold(
        derivation.derive(format!("{:x}", threshold).as_bytes()),
        |acc, pk| {
            SelfAddressingPrefix::new(
                derivation.to_owned(),
                acc.derivative()
                    .iter()
                    .zip(derivation.derive(pk.to_str().as_bytes()).derivative())
                    .map(|(acc_byte, pk_byte)| acc_byte ^ pk_byte)
                    .collect(),
            )
        },
    )
}

mod empty_string_as_none {
    use serde::{de::IntoDeserializer, Deserialize, Deserializer, Serializer};

    pub fn deserialize<'d, D, T>(de: D) -> Result<Option<T>, D::Error>
    where
        D: Deserializer<'d>,
        T: Deserialize<'d>,
    {
        let opt = Option::<String>::deserialize(de)?;
        let opt = opt.as_ref().map(String::as_str);
        match opt {
            None | Some("") => Ok(None),
            Some(s) => T::deserialize(s.into_deserializer()).map(Some),
        }
    }

    pub fn serialize<S, T>(t: &Option<T>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: ToString,
    {
        s.serialize_str(&match &t {
            Some(v) => v.to_string(),
            None => "".into(),
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct WitnessConfig {
    #[serde(rename = "bt", with = "SerHex::<Compact>")]
    pub tally: u64,

    #[serde(rename = "br")]
    pub prune: Vec<BasicPrefix>,

    #[serde(rename = "ba")]
    pub graft: Vec<BasicPrefix>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct InceptionWitnessConfig {
    #[serde(rename = "bt", with = "SerHex::<Compact>")]
    pub tally: u64,

    #[serde(rename = "b")]
    pub initial_witnesses: Vec<BasicPrefix>,
}

#[test]
fn threshold() {
    // test data taken from kid0003
    let sith = 2;
    let keys: Vec<BasicPrefix> = [
        "BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE",
        "BujP_71bmWFVcvFmkE9uS8BTZ54GIstZ20nj_UloF8Rk",
        "B8T4xkb8En6o0Uo5ZImco1_08gT5zcYnXzizUPVNzicw",
    ]
    .iter()
    .map(|k| k.parse().unwrap())
    .collect();

    let nxt = nxt_commitment(sith, &keys, &SelfAddressing::Blake3_256);

    assert_eq!(
        &nxt.to_str(),
        "ED8YvDrXvGuaIVZ69XsBVA5YN2pNTfQOFwgeloVHeWKs"
    )
}
