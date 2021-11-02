use base64::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::{
    error::Error,
    event::sections::seal::EventSeal,
    prefix::{
        AttachedSignaturePrefix, BasicPrefix, Prefix, SelfAddressingPrefix, SelfSigningPrefix,
    },
};

use super::payload_size::PayloadType;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub enum Attachment {
    SealSourceCouplets(Vec<SourceSeal>),
    AttachedEventSeal(Vec<EventSeal>),
    AttachedSignatures(Vec<AttachedSignaturePrefix>),
    ReceiptCouplets(Vec<(BasicPrefix, SelfSigningPrefix)>),
}

impl Attachment {
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        let (payload_type, att_len, serialized_attachment) = match self {
            Attachment::SealSourceCouplets(sources) => {
                let serialzied_sources: Vec<u8> = sources
                    .into_iter()
                    .map(|s| s.pack() )
                    .flatten()
                    .collect();

                (PayloadType::MG, sources.len(), serialzied_sources)
            }
            Attachment::AttachedEventSeal(seal) => {
                let serialized_seals: Vec<u8> = seal
                    .iter()
                    .map(|seal| {
                        [
                            seal.prefix.to_str(),
                            pack_sn(seal.sn),
                            seal.event_digest.to_str(),
                        ]
                        .join("")
                        .as_bytes()
                        .to_vec()
                    })
                    .flatten()
                    .collect();
                (PayloadType::MF, seal.len(), serialized_seals)
            }
            Attachment::AttachedSignatures(sigs) => {
                let serialized_sigs: Vec<u8> = sigs
                    .iter()
                    .map(|sig| sig.to_str().as_bytes().to_vec())
                    .flatten()
                    .collect();
                (PayloadType::MA, sigs.len(), serialized_sigs)
            }
            Attachment::ReceiptCouplets(couplets) => {
                let packed_couplets = couplets
                    .iter()
                    .map(|(bp, sp)| [bp.to_str(), sp.to_str()].join("").as_bytes().to_vec())
                    .fold(vec![], |acc, next| [acc, next].concat());

                (PayloadType::MC, couplets.len(), packed_couplets)
            }
        };
        Ok(payload_type
            .adjust_with_num(att_len as u16)
            .as_bytes()
            .to_vec()
            .into_iter()
            .chain(serialized_attachment)
            .collect::<Vec<_>>())
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
    pub fn pack(&self) -> Vec<u8> {
        [pack_sn(self.sn), self.digest.to_str()]
            .join("")
            .as_bytes()
            .to_vec()
    }
}

fn pack_sn(sn: u64) -> String {
    let payload_type = PayloadType::OA;
    let sn_raw: Vec<u8> = sn.to_be_bytes().into();
    // Calculate how many zeros are missing to achieve expected base64 string
    // length. Master code size is expected padding size.
    let missing_zeros =
        payload_type.size() / 4 * 3 - payload_type.master_code_size(false) - sn_raw.len();
    let sn_vec: Vec<u8> = std::iter::repeat(0)
        .take(missing_zeros)
        .chain(sn_raw)
        .collect();
    [
        payload_type.to_string(),
        base64::encode_config(sn_vec, URL_SAFE_NO_PAD),
    ]
    .join("")
}
