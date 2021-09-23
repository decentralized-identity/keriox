use std::str::FromStr;

use base64::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::{
    error::Error,
    prefix::{Prefix, SelfAddressingPrefix},
};

use super::{parse::counter, payload_size::PayloadType};

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub enum Attachement {
    SealSourceCouplets(Vec<SorceSeal>),
}

impl Attachement {
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        match self {
            Attachement::SealSourceCouplets(sources) => {
                let payload_type = PayloadType::MG;
                let serialzied_sources = sources
                    .into_iter()
                    .map(|s| s.serialize().unwrap())
                    .flatten();
                Ok(payload_type
                    .encode(sources.len() as u16)
                    .as_bytes()
                    .to_vec()
                    .into_iter()
                    .chain(serialzied_sources)
                    .collect::<Vec<_>>())
            }
        }
    }
}

impl FromStr for Attachement {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[0..2] {
            "-G" => {
                let (rest, counter) = counter(s.as_bytes())
                    .map_err(|_e| Error::SemanticError("Can't parse counter".into()))?;
                if rest.is_empty() {
                    Ok(counter)
                } else {
                    Err(Error::SemanticError("Can't parse counter".into()))
                }
            }
            _ => todo!(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SorceSeal {
    pub sn: u64,
    pub digest: SelfAddressingPrefix,
}

impl SorceSeal {
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
    let len = payload_type.size() - payload_type.master_code_size(false);
    let sn_raw: Vec<u8> = sn.to_be_bytes().into();
    let padding = 4 - len % 4;
    let len = (len + padding) / 4 * 3 - padding - sn_raw.len();
    let sn_vec: Vec<u8> = std::iter::repeat(0).take(len).chain(sn_raw).collect();
    [
        payload_type.to_string(),
        base64::encode_config(sn_vec, URL_SAFE_NO_PAD),
    ]
    .join("")
}

#[test]
fn test_parse_attachement() -> Result<(), Error> {
    let attached_str = "-GAC0AAAAAAAAAAAAAAAAAAAAAAQE3fUycq1G-P1K1pL2OhvY6ZU-9otSa3hXiCcrxuhjyII0AAAAAAAAAAAAAAAAAAAAAAQE3fUycq1G-P1K1pL2OhvY6ZU-9otSa3hXiCcrxuhjyII";
    let attached_sn_dig: Attachement = attached_str.parse()?;
    assert_eq!(
        attached_str,
        String::from_utf8(attached_sn_dig.serialize()?).unwrap()
    );
    match attached_sn_dig {
        Attachement::SealSourceCouplets(sources) => {
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
        }
    };
    Ok(())
}
