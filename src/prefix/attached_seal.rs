use std::str::FromStr;
use base64::URL_SAFE;
use serde::{Serialize, Deserialize};
use crate::{error::Error, event::sections::seal::EventSeal};
use super::Prefix;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttachedEventSeal {
    pub event_seal: EventSeal,
}

impl AttachedEventSeal {
    pub fn new(seal: EventSeal) -> Self {
        Self { event_seal: seal }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        Ok([
            "-FAB".as_bytes().to_vec(),
            self.event_seal.prefix.to_str().as_bytes().to_vec(),
            "0A".as_bytes().to_vec(),
            num_to_base_64(self.event_seal.sn)?.as_bytes().to_vec(),
            self.event_seal.event_digest.to_str().as_bytes().to_vec(),
        ]
        .concat())
    }
}

fn num_to_base_64(sn: u64) -> Result<String, Error> {
    let mut tmp = vec![0, 0, 0, 0, 0, 0, 0, 0];
    tmp.extend(u64::to_be_bytes(sn).to_vec());
    Ok((&base64::encode_config(tmp, URL_SAFE)[..22]).to_string())
}

impl FromStr for AttachedEventSeal {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[0..3] {
            "FAB" => {
                let event_seal = EventSeal::default();
                Ok(AttachedEventSeal { event_seal })
            }
            _ => Err(Error::SemanticError("Can't parse event seal".into())),
        }
    }
}
