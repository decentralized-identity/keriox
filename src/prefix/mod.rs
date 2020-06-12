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
        match parse_padded(str) {
            Ok((drv, padding_length)) => Ok(Prefix {
                derivation_code: drv,
                derivative: decode_config(&str[padding_length..], base64::URL_SAFE)
                    .map_err(|_| Error)?,
            }),
            Err(e) => Err(e),
        }
    }
}

impl Prefix {
    pub fn to_str(&self) -> String {
        let encoded_derivative = encode_config(&self.derivative, base64::URL_SAFE);
        let padding = get_prefix_length(&encoded_derivative);
        [
            self.derivation_code.to_str(),
            &encoded_derivative[..encoded_derivative.len() - padding],
        ]
        .join("")
    }
}

fn parse_padded(padded_code: &str) -> Result<(Derivation, usize), Error> {
    let head = &padded_code[..1];

    match head {
        "0" => Ok((Derivation::from_str(&padded_code[..2])?, 2)),
        "1" => Ok((Derivation::from_str(&padded_code[..3])?, 3)),
        "2" => Ok((Derivation::from_str(&padded_code[..4])?, 4)),
        _ => Ok((Derivation::from_str(&head)?, 1)),
    }
}

/// Counts the number of padding bytes (=) in a base64 encoded string,
/// based on which returns the size we should use for the prefix bytes.
/// Section 14. Derivation Codes.

pub fn get_prefix_length(value: &str) -> usize {
    return value.matches('=').count();
}
