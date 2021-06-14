use std::str::FromStr;

use fraction::Fraction;
use fraction::One;
use fraction::Zero;
use serde::{
    de::{self},
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_hex::{Compact, SerHex};

use crate::{
    derivation::self_addressing::SelfAddressing,
    error::Error,
    prefix::{AttachedSignaturePrefix, BasicPrefix, Prefix, SelfAddressingPrefix},
};

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct KeyConfig {
    #[serde(rename = "kt")]
    pub threshold: SignatureThreshold,

    #[serde(rename = "k")]
    pub public_keys: Vec<BasicPrefix>,

    #[serde(rename = "n", with = "empty_string_as_none")]
    pub threshold_key_digest: Option<SelfAddressingPrefix>,
}

impl KeyConfig {
    pub fn new(
        public_keys: Vec<BasicPrefix>,
        threshold_key_digest: Option<SelfAddressingPrefix>,
        threshold: Option<SignatureThreshold>,
    ) -> Self {
        Self {
            threshold: threshold.map_or_else(
                || SignatureThreshold::Simple(public_keys.len() as u64 / 2 + 1),
                |t| t,
            ),
            public_keys,
            threshold_key_digest,
        }
    }

    /// Verify
    ///
    /// Verifies the given sigs against the given message using the KeyConfigs
    /// Public Keys, according to the indexes in the sigs.
    pub fn verify(&self, message: &[u8], sigs: &[AttachedSignaturePrefix]) -> Result<bool, Error> {
        let enough_sigs = match self.threshold {
            SignatureThreshold::Simple(ref t) => (sigs.len() as u64) >= t.to_owned(),
            SignatureThreshold::Weighted(ref t) => {
                sigs.into_iter().fold(Zero::zero(), |acc: Fraction, sig| {
                    acc + t[sig.index as usize].fraction
                }) >= One::one()
            }
        };
        // ensure there's enough sigs
        if !enough_sigs {
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
        nxt_commitment(&self.threshold, &self.public_keys, derivation)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ThresholdFraction {
    fraction: Fraction,
}

impl ThresholdFraction {
    pub fn new(n: u64, d: u64) -> Self {
        Self {
            fraction: Fraction::new(n, d),
        }
    }
}

impl FromStr for ThresholdFraction {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let f: Vec<_> = s.split("/").collect();
        if f.len() != 2 {
            return Err(Error::SemanticError("Improper threshold fraction".into()));
        }
        let a = f[0].parse::<u64>()?;
        let b = f[1].parse::<u64>()?;
        Ok(ThresholdFraction {
            fraction: Fraction::new(a, b),
        })
    }
}
impl<'de> Deserialize<'de> for ThresholdFraction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(de::Error::custom)
    }
}

impl Serialize for ThresholdFraction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}", self.fraction))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum SignatureThreshold {
    #[serde(with = "SerHex::<Compact>")]
    Simple(u64),
    Weighted(Vec<ThresholdFraction>),
}

impl SignatureThreshold {
    fn simple(t: u64) -> Self {
        Self::Simple(t)
    }
    fn weighted(frac: Vec<(u64, u64)>) -> Self {
        let fractions: Vec<ThresholdFraction> = frac
            .into_iter()
            .map(|(n, d)| ThresholdFraction::new(n, d))
            .collect();
        Self::Weighted(fractions)
    }
}

impl Default for SignatureThreshold {
    fn default() -> Self {
        Self::Simple(0)
    }
}

/// Serialize For Commitment
///
/// Serializes a threshold and key set into the form
/// required for threshold key digest creation
pub fn nxt_commitment(
    threshold: &SignatureThreshold,
    keys: &[BasicPrefix],
    derivation: &SelfAddressing,
) -> SelfAddressingPrefix {
    let limen = match threshold {
        SignatureThreshold::Simple(n) => format!("{:x}", n),
        SignatureThreshold::Weighted(th) => th
            .into_iter()
            .map(|frac| format!("{}", frac.fraction))
            .collect::<Vec<String>>()
            .join(","),
    };
    keys.iter()
        .fold(derivation.derive(limen.as_bytes()), |acc, pk| {
            SelfAddressingPrefix::new(
                derivation.to_owned(),
                acc.derivative()
                    .iter()
                    .zip(derivation.derive(pk.to_str().as_bytes()).derivative())
                    .map(|(acc_byte, pk_byte)| acc_byte ^ pk_byte)
                    .collect(),
            )
        })
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

#[test]
fn test_next_commitment() {
    // test data taken from kid0003
    let keys: Vec<BasicPrefix> = [
        "BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE",
        "BujP_71bmWFVcvFmkE9uS8BTZ54GIstZ20nj_UloF8Rk",
        "B8T4xkb8En6o0Uo5ZImco1_08gT5zcYnXzizUPVNzicw",
    ]
    .iter()
    .map(|k| k.parse().unwrap())
    .collect();

    let sith = SignatureThreshold::Simple(2);
    let nxt = nxt_commitment(&sith, &keys, &SelfAddressing::Blake3_256);

    assert_eq!(
        &nxt.to_str(),
        "ED8YvDrXvGuaIVZ69XsBVA5YN2pNTfQOFwgeloVHeWKs"
    );

    // test data taken from keripy
    // (keripy/tests/core/test_weighted_threshold.py::test_weighted)
    // Set weighted threshold to "[1/2, 1/2, 1/2]"
    let sith = SignatureThreshold::weighted(vec![(1, 2), (1, 2), (1, 2)]);
    let next_keys: Vec<BasicPrefix> = [
        "DeonYM2bKnAwp6VZcuCXdX72kNFw56czlZ_Tc7XHHVGI",
        "DQghKIy-2do9OkweSgazh3Ql1vCOt5bnc5QF8x50tRoU",
        "DNAUn-5dxm6b8Njo01O0jlStMRCjo9FYQA2mfqFW1_JA",
    ]
    .iter()
    .map(|x| x.parse().unwrap())
    .collect();
    let nxt = nxt_commitment(&sith, &next_keys, &SelfAddressing::Blake3_256);
    assert_eq!(nxt.to_str(), "EhJGhyJQTpSlZ9oWfQT-lHNl1woMazLC42O89fRHocTI");
}

#[test]
fn test_threshold() -> Result<(), Error> {
    use crate::derivation::{basic::Basic, self_signing::SelfSigning};
    use crate::keys::Key;
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;

    let (pub_keys, priv_keys): (Vec<BasicPrefix>, Vec<Key>) = [0, 1, 2]
        .iter()
        .map(|_| {
            let kp = Keypair::generate(&mut OsRng);
            (
                Basic::Ed25519.derive(Key::new(kp.public.to_bytes().to_vec())),
                Key::new(kp.secret.to_bytes().to_vec()),
            )
        })
        .unzip();
    let current_threshold = SignatureThreshold::weighted(vec![(1, 4), (1, 2), (1, 2)]);

    let next_key_hash = {
        let next_threshold = SignatureThreshold::weighted(vec![(1, 2), (1, 2)]);
        let next_keys: Vec<BasicPrefix> = [1, 2]
            .iter()
            .map(|_| {
                let kp = Keypair::generate(&mut OsRng);
                Basic::Ed25519.derive(Key::new(kp.public.to_bytes().to_vec()))
            })
            .collect();
        nxt_commitment(&next_threshold, &next_keys, &SelfAddressing::Blake3_256)
    };
    let key_config = KeyConfig::new(pub_keys, Some(next_key_hash), Some(current_threshold));

    let msg_to_sign = "message to signed".as_bytes();

    let mut signatures = vec![];
    for i in 0..priv_keys.len() {
        let sig = priv_keys[i].sign_ed(msg_to_sign)?;
        signatures.push(AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            sig,
            i as u16,
        ));
    }

    // All signatures.
    let st = key_config.verify(
        msg_to_sign,
        &vec![
            signatures[0].clone(),
            signatures[1].clone(),
            signatures[2].clone(),
        ],
    );
    assert!(matches!(st, Ok(true)));

    // Not enough signatures.
    let st = key_config.verify(
        msg_to_sign,
        &vec![signatures[0].clone(), signatures[2].clone()],
    );
    assert!(matches!(st, Err(Error::NotEnoughSigsError)));

    // Enough signatures.
    let st = key_config.verify(
        msg_to_sign,
        &vec![signatures[1].clone(), signatures[2].clone()],
    );
    assert!(matches!(st, Ok(true)));

    // The same signatures.
    let st = key_config.verify(
        msg_to_sign,
        &vec![
            signatures[0].clone(),
            signatures[0].clone(),
            signatures[0].clone(),
        ],
    );
    assert!(matches!(st, Err(Error::NotEnoughSigsError)));

    Ok(())
}

#[test]
fn test_verify() -> Result<(), Error> {
    use crate::event::event_data::EventData;
    use crate::event_message::parse;
    use crate::event_message::parse::Deserialized;

    // test data taken from keripy
    // (keripy/tests/core/test_weighted_threshold.py::test_weighted)
    let ev = br#"{"v":"KERI10JSON00015b_","i":"EX0WJtv6vc0IWzOqa92Pv9v9pgs1f0BfIVrSch648Zf0","s":"0","t":"icp","kt":["1/2","1/2","1/2"],"k":["DK4OJI8JOr6oEEUMeSF_X-SbKysfwpKwW-ho5KARvH5c","D1RZLgYke0GmfZm-CH8AsW4HoTU4m-2mFgu8kbwp8jQU","DBVwzum-jPfuUXUcHEWdplB4YcoL3BWGXK0TMoF_NeFU"],"n":"EhJGhyJQTpSlZ9oWfQT-lHNl1woMazLC42O89fRHocTI","bt":"0","b":[],"c":[],"a":[]}-AADAAKWMK8k4Po2A0rBrUBjBom73DfTCNg_biwR-_LWm6DMHZHGDfCuOmEyR8sEdp7cPxhsavq4istIZ_QQ42yyUcDAABeTClYkN-yjbW3Kz3ot6MvAt5Se-jmcjhu-Cfsv4m_GKYgc_qwel1SbAcqF0TiY0EHFdjNKvIkg3q19KlhSbuBgACA6QMnsnZuy66xrZVg3c84mTodZCEvOFrAIDQtm8jeXeCTg7yFauoQECZyNIlUnnxVHuk2_Fqi5xK_Lu9Pt76Aw"#;
    let signed_msg = parse::signed_message(ev).unwrap();
    match signed_msg.1 {
        Deserialized::Event(ref e) => {
            if let EventData::Icp(icp) = e.to_owned().event.event.event.event_data {
                let kc = icp.key_config;
                let msg = e.clone().event.event.serialize()?;
                assert!(kc.verify(&msg, &e.signatures)?);
            }
        }
        _ => (),
    };

    Ok(())
}
