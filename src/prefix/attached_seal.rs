use std::{convert::TryInto, str::FromStr};

use keri::{derivation::{DerivationCode, attached_signature_code::b64_to_num, self_addressing::SelfAddressing}, event::sections::seal::EventSeal, prefix::{IdentifierPrefix, Prefix, SelfAddressingPrefix, parse::basic_prefix}};
use nom::{bytes::complete::take, combinator::map_parser, error::ErrorKind, sequence::tuple};

use crate::error::Error;

pub struct AttachedSeal {
    event_seal: EventSeal,
}

impl Prefix for AttachedSeal {
    fn derivative(&self) -> Vec<u8> {
        todo!()
    }

    fn derivation_code(&self) -> String {
        "FAB".to_string()    
    }
}

impl FromStr for AttachedSeal {
    type Err = keri::error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[0..3] {
            "FAB" =>  {
                let event_seal = EventSeal::default();
                Ok(AttachedSeal {event_seal})
            }
            _ => {Err(keri::error::Error::SemanticError("Can't parse event seal".into()))}
        }
    }
}
