use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{error::Error, prefix::{Prefix, SelfAddressingPrefix}};

use super::{parse::counter, payload_size::{PayloadType, num_to_base_64}};

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub enum Counter {
    SealSourceCouplets(Vec<AttachedSnDigest>),
}

impl Counter {
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        match self {
            Counter::SealSourceCouplets(sources) => {
                let payload_type = PayloadType::MG;
                let serialzied_sources = sources
                    .into_iter()
                    .map(|s| s.serialize().unwrap())
                    .flatten();
                Ok(payload_type.encode(sources.len() as u16).as_bytes().to_vec()
                .into_iter()
                .chain(serialzied_sources)
                .collect::<Vec<_>>())
            }
        }
    }
}

impl FromStr for Counter {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[0..2] {
            "-G" => {
                let (rest, counter) = counter(s.as_bytes()).map_err(|_e| Error::SemanticError("Can't parse counter".into()))?;
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
pub struct AttachedSnDigest {
    sn: u64,
    digest: SelfAddressingPrefix,
}

impl AttachedSnDigest {
    pub fn new(sn: u64, digest: SelfAddressingPrefix) -> Self {
        Self {sn, digest}
    }
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        let payload_type = PayloadType::OA;
        Ok([
            payload_type.to_string().as_bytes().to_vec(),
            // TODO remove magic 22
            num_to_base_64(self.sn as u16, 22).as_bytes().to_vec(),
            self.digest.to_str().as_bytes().to_vec(),
        ]
        .concat())
    }
}



#[test]
fn test_parse_attachement() -> Result<(), Error> {
    let attached_str = "-GAC0AAAAAAAAAAAAAAAAAAAAAAQE3fUycq1G-P1K1pL2OhvY6ZU-9otSa3hXiCcrxuhjyII0AAAAAAAAAAAAAAAAAAAAAAQE3fUycq1G-P1K1pL2OhvY6ZU-9otSa3hXiCcrxuhjyII";
    let attached_sn_dig: Counter = attached_str.parse()?;
    assert_eq!(
        attached_str,
        String::from_utf8(attached_sn_dig.serialize()?).unwrap()
    );
    match attached_sn_dig {
        Counter::SealSourceCouplets(sources) => {
            let s1 = sources[0].clone();
            let s2 = sources[1].clone();
            assert_eq!(s1.sn, 16);
            assert_eq!(
                s1.digest.to_str(),
                "E3fUycq1G-P1K1pL2OhvY6ZU-9otSa3hXiCcrxuhjyII"
            );
            assert_eq!(s2.sn, 16);
            assert_eq!(
                s2.digest.to_str(),
                "E3fUycq1G-P1K1pL2OhvY6ZU-9otSa3hXiCcrxuhjyII"
            );
        }
    };
    Ok(())
}
