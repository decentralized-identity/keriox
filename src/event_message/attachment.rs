use std::{convert::TryFrom, str::FromStr};

use base64::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::{error::Error, event::sections::seal::EventSeal, prefix::{Prefix, SelfAddressingPrefix}};

use super::{parse::{event_seals, source_seal}, payload_size::PayloadType};

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub enum Attachment {
    SealSourceCouplets(Vec<SourceSeal>),
    AttachedEventSeal(Vec<EventSeal>),
}

impl Attachment {
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        match self {
            Attachment::SealSourceCouplets(sources) => {
                let payload_type = PayloadType::MG;
                let serialzied_sources = sources
                    .into_iter()
                    .map(|s| s.serialize().unwrap())
                    .flatten();
                Ok(payload_type
                    .adjust_with_num(sources.len() as u16)
                    .as_bytes()
                    .to_vec()
                    .into_iter()
                    .chain(serialzied_sources)
                    .collect::<Vec<_>>())
            }
            Attachment::AttachedEventSeal(seal) => {
                let payload_type = PayloadType::MF;
                let serialized_seals: String = seal.iter().fold("".into(), |acc, seal| {
                    [
                    acc,
                    seal.prefix.to_str(),
                    pack_sn(seal.sn),
                    seal.event_digest.to_str(),
                    ].join("")
                });
                Ok(payload_type
                    .adjust_with_num(seal.len() as u16)
                    .as_bytes()
                    .to_vec()
                    .into_iter()
                    .chain(serialized_seals.as_bytes().to_vec())
                    .collect::<Vec<_>>())
            },
        }
    }
}

impl FromStr for Attachment {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let payload_type: PayloadType = PayloadType::try_from(&s[0..2])?;
        match  payload_type {
            PayloadType::MG => {
                let (rest, source_seals) = source_seal(&s[2..].as_bytes())
                    .map_err(|_e| Error::SemanticError("Can't parse source seal".into()))?;
                if rest.is_empty() {
                    Ok(Attachment::SealSourceCouplets(source_seals))
                } else {
                    Err(Error::SemanticError("Can't parse source seal".into()))
                }
            },
            PayloadType::MF => {
                let (rest, event_seals) = event_seals(&s[2..].as_bytes())
                    .map_err(|_e| Error::SemanticError("Can't parse event seal".into()))?;
                    if rest.is_empty() {
                    Ok(Attachment::AttachedEventSeal(event_seals))
                } else {
                    Err(Error::SemanticError("Can't parse event seal".into()))
                }
            },
            _ => Err(Error::DeserializeError("Unknown counter code".into())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SourceSeal {
    pub sn: u64,
    pub digest: SelfAddressingPrefix,
}

impl SourceSeal {
    pub fn new(sn: u64, digest: SelfAddressingPrefix) -> Self {
        Self { sn, digest }
    }
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        Ok([pack_sn(self.sn), self.digest.to_str()]
            .join("")
            .as_bytes()
            .to_vec())
    }
}

fn pack_sn(sn: u64) -> String {
    let payload_type = PayloadType::OA;
    let sn_raw: Vec<u8> = sn.to_be_bytes().into();
    // Calculate how many zeros are missing to achieve expected base64 string
    // length. Master code size is expected padding size.
    let missing_zeros = payload_type.size() / 4 * 3 - payload_type.master_code_size(false) - sn_raw.len();
    let sn_vec: Vec<u8> = std::iter::repeat(0).take(missing_zeros).chain(sn_raw).collect();
    [
        payload_type.to_string(),
        base64::encode_config(sn_vec, URL_SAFE_NO_PAD),
    ]
    .join("")
}

#[test]
fn test_parse_attachement() -> Result<(), Error> {
    let attached_str = "-GAC0AAAAAAAAAAAAAAAAAAAAAAQE3fUycq1G-P1K1pL2OhvY6ZU-9otSa3hXiCcrxuhjyII0AAAAAAAAAAAAAAAAAAAAAAQE3fUycq1G-P1K1pL2OhvY6ZU-9otSa3hXiCcrxuhjyII";
    let attached_sn_dig: Attachment = attached_str.parse()?;
    assert_eq!(
        attached_str,
        String::from_utf8(attached_sn_dig.serialize()?).unwrap()
    );
    match attached_sn_dig {
        Attachment::SealSourceCouplets(sources) => {
            let s1 = sources[0].clone();
            let s2 = sources[1].clone();
            assert_eq!(s1.sn, 1);
            assert_eq!(
                s1.digest.to_str(),
                "E3fUycq1G-P1K1pL2OhvY6ZU-9otSa3hXiCcrxuhjyII"
            );
            assert_eq!(s2.sn, 1);
            assert_eq!(
                s2.digest.to_str(),
                "E3fUycq1G-P1K1pL2OhvY6ZU-9otSa3hXiCcrxuhjyII"
            );
        },
        _ => {}
    };
    Ok(())
}
