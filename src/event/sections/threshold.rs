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
    Weighted(Vec<ThresholdFraction>),
}

impl SignatureThreshold {
    pub fn simple(t: u64) -> Self {
        Self::Simple(t)
    }
    pub fn weighted(frac: Vec<(u64, u64)>) -> Self {
        let fractions: Vec<ThresholdFraction> = frac
            .into_iter()
            .map(|(n, d)| ThresholdFraction::new(n, d))
            .collect();
        Self::Weighted(fractions)
    }

    pub fn enough_signatures(&self, sigs: &[AttachedSignaturePrefix]) -> Result<bool, Error> {
        Ok(match self {
            SignatureThreshold::Simple(ref t) => (sigs.len() as u64) >= t.to_owned(),
            SignatureThreshold::Weighted(ref t) => {
                sigs.into_iter().fold(Zero::zero(), |acc: Fraction, sig| {
                    acc + t[sig.index as usize].fraction
                }) >= One::one()
            }
        })
    }
}

impl Default for SignatureThreshold {
    fn default() -> Self {
        Self::Simple(0)
    }
}
