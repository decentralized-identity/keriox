use std::{fmt, str::FromStr};

use crate::{error::Error, prefix::AttachedSignaturePrefix};
use fraction::{Fraction, One, Zero};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_hex::{Compact, SerHex};

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

impl fmt::Display for ThresholdFraction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.fraction)
    }
}

impl FromStr for ThresholdFraction {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let f: Vec<_> = s.split("/").collect();
        if f.len() > 2 {
            Err(Error::SemanticError("Improper threshold fraction".into()))
        } else if f.len() == 1 {
            let a = f[0].parse::<u64>()?;
            Ok(ThresholdFraction {
                fraction: Fraction::new(a, 1u64),
            })
        } else {
            let a = f[0].parse::<u64>()?;
            let b = f[1].parse::<u64>()?;
            Ok(ThresholdFraction {
                fraction: Fraction::new(a, b),
            })
        }
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
    Weighted(WeightedThreshold),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum WeightedThreshold {
    Single(ThresholdClause),
    Multi(MultiClauses),
}

impl WeightedThreshold {
    pub fn enough_signatures(&self, sigs: &[AttachedSignaturePrefix]) -> Result<bool, Error> {
        match self {
            WeightedThreshold::Single(clause) => clause.enough_signatures(0, sigs),
            WeightedThreshold::Multi(clauses) => clauses.enough_signatures(sigs),
        }
    }

    /// Serialize For Commitment
    ///
    /// Serializes a threshold into the form required 
    /// for next keys commitment.
    /// Example: 
    ///     [["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]] 
    ///     is serialized to
    ///     '1/2,1/2,1/4,1/4,1/4&1,1'
    pub fn extract_threshold(&self) -> String {
        match self {
            WeightedThreshold::Single(clause) => clause.extract_threshold(),
            WeightedThreshold::Multi(clauses) => clauses.extract_threshold(),
        }
    }
}

impl SignatureThreshold {
    pub fn simple(t: u64) -> Self {
        Self::Simple(t)
    }

    pub fn single_weighted(fracs: Vec<(u64, u64)>) -> Self {
        Self::Weighted(WeightedThreshold::Single(ThresholdClause::new_from_tuples(
            fracs,
        )))
    }

    pub fn multi_weighted(fracs: Vec<Vec<(u64, u64)>>) -> Self {
        Self::Weighted(WeightedThreshold::Multi(MultiClauses::new_from_tuples(
            fracs,
        )))
    }

    pub fn enough_signatures(&self, sigs: &[AttachedSignaturePrefix]) -> Result<bool, Error> {
        match self {
            SignatureThreshold::Simple(ref t) => Ok((sigs.len() as u64) >= t.to_owned()),
            SignatureThreshold::Weighted(ref thresh) => thresh.enough_signatures(sigs), 
        }
    }
}

impl Default for SignatureThreshold {
    fn default() -> Self {
        Self::Simple(0)
    }
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ThresholdClause(Vec<ThresholdFraction>);

impl ThresholdClause {
    pub fn new(fracs: &[ThresholdFraction]) -> Self {
        Self(fracs.to_owned())
    }

    pub fn new_from_tuples(tuples: Vec<(u64, u64)>) -> Self {
        let clause = tuples
            .into_iter()
            .map(|(n, d)| ThresholdFraction::new(n, d))
            .collect();
        Self(clause)
    }

    pub fn enough_signatures(
        &self,
        start_index: u64,
        sigs: &[AttachedSignaturePrefix],
    ) -> Result<bool, Error> {
        Ok(sigs.into_iter().fold(Zero::zero(), |acc: Fraction, sig| {
            acc + self.0[(sig.index as u64 - start_index) as usize].fraction
        }) >= One::one())
    }

    pub fn extract_threshold(&self) -> String {
        self.0
            .iter()
            .map(|fr| fr.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct MultiClauses(Vec<ThresholdClause>);

impl MultiClauses {
    pub fn new(fracs: Vec<Vec<ThresholdFraction>>) -> Self {
        let clauses = fracs
            .iter()
            .map(|clause| ThresholdClause::new(clause))
            .collect();

        Self(clauses)
    }

    pub fn new_from_tuples(fracs: Vec<Vec<(u64, u64)>>) -> Self {
        let wt = fracs
            .into_iter()
            .map(|clause| ThresholdClause::new_from_tuples(clause))
            .collect();
        MultiClauses(wt)
    }

    pub fn enough_signatures(&self, sigs: &[AttachedSignaturePrefix]) -> Result<bool, Error> {
        let mut out = true;
        let mut start_index = 0u16;
        for clause in self.0.iter() {
            // let 
            let end_index = start_index + clause.0.len() as u16;
            let signatures: Vec<AttachedSignaturePrefix> = sigs
                .to_owned()
                .into_iter()
                .filter(|sig| sig.index >= start_index && sig.index < end_index)
                .collect();
            out = out && clause.enough_signatures(start_index as u64, &signatures)?;
            start_index = end_index;
        }

        Ok(out)
    }

    pub fn extract_threshold(&self) -> String {
        self.0
            .iter()
            .map(|clause| clause.extract_threshold())
            .collect::<Vec<_>>()
            .join("&")
    }
}

#[test]
fn test_enough_sigs() -> Result<(), Error> {
    use crate::derivation::self_signing::SelfSigning;
    // Threshold: [[1/1], [1/2, 1/2, 1/2], [1/2,1/2]]
    let wt = MultiClauses::new_from_tuples(vec![vec![(1, 1)], vec![(1, 2), (1, 2), (1, 2)]]);
    let dump_signatures: Vec<_> = vec![0, 1, 2, 3]
        .iter()
        .map(|x| AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, vec![], x.to_owned()))
        .collect();

    // All signatures.
    assert!(wt.enough_signatures(&dump_signatures.clone())?);

    // Enough signatures.
    let enough = vec![
        dump_signatures[0].clone(),
        dump_signatures[1].clone(),
        dump_signatures[3].clone(),
    ];
    assert!(wt.enough_signatures(&enough.clone())?);

    let not_enough = vec![dump_signatures[0].clone()];
    assert!(!wt.enough_signatures(&not_enough.clone())?);

    Ok(())
}

#[test]
pub fn test_weighted_treshold_serialization() -> Result<(), Error> {
    let multi_threshold = r#"[["1"],["1/2","1/2","1/2"]]"#.to_string();
    let wt: WeightedThreshold = serde_json::from_str(&multi_threshold)?;
    assert!(matches!(wt, WeightedThreshold::Multi(_)));
    assert_eq!(serde_json::to_string(&wt).unwrap(), multi_threshold);

    let single_threshold = r#"["1/2","1/2","1/2"]"#.to_string();
    let wt: WeightedThreshold = serde_json::from_str(&single_threshold)?;
    assert!(matches!(wt, WeightedThreshold::Single(_)));
    assert_eq!(serde_json::to_string(&wt).unwrap(), single_threshold);
    Ok(())
}
