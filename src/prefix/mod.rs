use crate::derivation::{Derivation, Derivative};
use base64::{decode_config, encode_config};
use core::{
    fmt::{Display, Error, Formatter},
    str::FromStr,
};

#[derive(Debug, PartialEq)]
pub struct Prefix {
    pub derivation_code: Derivation,
    pub derivative: Derivative,
}

impl Display for Prefix {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{}", self.to_str())
    }
}

impl FromStr for Prefix {
    type Err = Error;
    fn from_str(str: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl Prefix {
    pub fn to_str(&self) -> String {
        todo!()
    }
