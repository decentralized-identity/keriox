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
                derivative: decode_config(&str[padding_length..], base64::URL_SAFE).unwrap(), // TODO HACK
            }),
            Err(e) => Err(e),
        }
    }
}

impl Prefix {
    pub fn to_str(&self) -> String {
        todo!()
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

// TODO in future, derivation codes may have >1 char representations,
// number of 0s will become dependant on derivation code value as well
fn pad_to_length(derivation_code: &Derivation, len: usize) -> String {
    let prefix = match len % 4 {
        3 => "10",
        2 => "0",
        1 => "",
        0 => "200",
        // HACK should NEVER happen given how % works
        _ => "",
    };

    [prefix, &derivation_code.to_str()].join("")
}

/// Counts the number of padding bytes (=) in a base64 encoded string,
/// based on which returns the size we should use for the prefix bytes.
/// Section 14. Derivation Codes.

pub fn get_prefix_length(value: &str) -> usize {
    return value.matches('=').count();
}
