use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{derivation::{attached_signature_code::{num_to_b64}}, error::Error, event_message::parse::{b64_count}, prefix::{Prefix, SelfAddressingPrefix, parse::{attached_sn, self_addressing_prefix}}};

use super::payload_size::PayloadType;

pub enum Counter {
    SealSourceCouplets(Vec<AttachedSnDigest>)
}

impl Counter {
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        match self {
            Counter::SealSourceCouplets(sources) => {
                let serialzied_sources = sources.into_iter().map(|s| s.serialize().unwrap()).flatten();
                Ok(vec![
                    PayloadType::MG.to_string().as_bytes().to_vec(),
                    // TODO AB?
                    num_to_base_64(sources.len() as u16, 2)?.as_bytes().to_vec(),
                ]
                .into_iter()
                .flatten()
                .chain(serialzied_sources)
                .collect::<Vec<_>>())
                },
        }
    }
}

impl FromStr for Counter {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[0..2] {
            "-G" => {
                let count = b64_count(&s[2..4].as_bytes()).unwrap().1;
                println!("count: {}", count);
                let sn_dig_vecs = (0..count)
                .fold(
                    Ok((s[4..].as_bytes(), vec![])), 
                    |acc: Result<_, Error>, _| {
                        let (rest, mut parsed) = acc?;
                        let (rest, sn) = attached_sn(rest)
                            .map_err(|_e| Error::SemanticError("Not enough sns in attachement".into()))?;
                        let (rest, digest) = self_addressing_prefix(rest)
                            .map_err(|_e| Error::SemanticError("Not enough digests in attachement".into()))?;
                        parsed.push(AttachedSnDigest { sn, digest });
                        Ok((rest, parsed))
                    }
                )?;
                    Ok(Counter::SealSourceCouplets(sn_dig_vecs.1))
            }
            _ => Err(Error::SemanticError("Can't parse attachement".into())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttachedSnDigest {
    sn: u64,
	digest: SelfAddressingPrefix,
}

impl AttachedSnDigest {
	pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        Ok([
            // TODO 0A?
            "0A".as_bytes().to_vec(),
            num_to_base_64(self.sn as u16, 22)?.as_bytes().to_vec(),
            self.digest.to_str().as_bytes().to_vec(),
        ]
        .concat())
    }
}

fn num_to_base_64(sn: u16, len: usize) -> Result<String, Error> {
    let i = num_to_b64(sn);
    let part = if i.len() < len {
        "A".repeat(len - i.len())
    } else {String::default()};
    Ok([part, i].join(""))
}

impl FromStr for AttachedSnDigest {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[0..4] {
            "-GAB" => {
            	let (rest, sn) = attached_sn(&s[4..].as_bytes()).unwrap();
				let (_rest, digest) = self_addressing_prefix(rest).unwrap();
                Ok(AttachedSnDigest { sn, digest })
            }
            _ => Err(Error::SemanticError("Can't parse attachement".into())),
        }
    }
}

#[test]
fn test_parse_attachement() -> Result<(), Error> {
	let attached_str = "-GAC0AAAAAAAAAAAAAAAAAAAAAAQE3fUycq1G-P1K1pL2OhvY6ZU-9otSa3hXiCcrxuhjyII0AAAAAAAAAAAAAAAAAAAAAAQE3fUycq1G-P1K1pL2OhvY6ZU-9otSa3hXiCcrxuhjyII";
	let attached_sn_dig: Counter = attached_str.parse()?;
    assert_eq!(attached_str, String::from_utf8(attached_sn_dig.serialize()?).unwrap());
    match attached_sn_dig {
        Counter::SealSourceCouplets(sources) => {
            let s1 = sources[0].clone();
            let s2 = sources[1].clone();
	        assert_eq!(s1.sn, 16);
	        assert_eq!(s1.digest.to_str(), "E3fUycq1G-P1K1pL2OhvY6ZU-9otSa3hXiCcrxuhjyII");
	        assert_eq!(s2.sn, 16);
	        assert_eq!(s2.digest.to_str(), "E3fUycq1G-P1K1pL2OhvY6ZU-9otSa3hXiCcrxuhjyII");
        },
    };
	Ok(())
}
