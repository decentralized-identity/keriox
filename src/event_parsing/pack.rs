use base64::URL_SAFE_NO_PAD;

use crate::{error::Error, event_message::{parse::{Attachment, Deserialized}, signed_event_message::{SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt}}, prefix::Prefix};

use super::payload_size::PayloadType;

pub trait Pack {
	fn pack(&self) -> Result<Vec<u8>, Error>;
}

impl Pack for Deserialized {
    fn pack(&self) -> Result<Vec<u8>, Error> {
       match self {
            Deserialized::Event(ev) => ev.pack(),
            Deserialized::NontransferableRct(ntr) => ntr.pack(),
            Deserialized::TransferableRct(tr) => tr.pack(),
        } 
    }
}

impl Pack for SignedEventMessage {
    fn pack(&self) -> Result<Vec<u8>, Error> {
        Ok([
            self.event_message.serialize()?,
            Attachment::AttachedSignatures(self.signatures.clone()).pack()?,
        ]
        .concat())
    }
}

impl Pack for SignedNontransferableReceipt {
    fn pack(&self) -> Result<Vec<u8>, Error> {
        Ok([
            self.body.serialize()?,
            Attachment::ReceiptCouplets(self.couplets.clone()).pack()?,
        ]
        .concat())
    }
}

impl Pack for SignedTransferableReceipt {
    fn pack(&self) -> Result<Vec<u8>, Error> {
        Ok([
                self.body.serialize()?,
                Attachment::AttachedEventSeal(vec![self.validator_seal.clone()]).pack()?,
                Attachment::AttachedSignatures(self.signatures.clone()).pack()?,
            ]
            .concat())
        }
    }


impl Pack for Attachment {
    fn pack(&self) -> Result<Vec<u8>, Error> {
         let (payload_type, att_len, serialized_attachment) = match self {
            Attachment::SealSourceCouplets(sources) => {
                let serialzied_sources = sources
                    .into_iter()
                    .fold("".into(), |acc, s| [acc, pack_sn(s.sn), s.digest.to_str()].join(""));

                (PayloadType::MG, sources.len(), serialzied_sources)
            }
            Attachment::AttachedEventSeal(seal) => {
                let serialized_seals = seal.iter().fold("".into(), |acc, seal| {
                    [
                        acc,
                        seal.prefix.to_str(),
                        pack_sn(seal.sn),
                        seal.event_digest.to_str(),
                    ]
                    .join("")
                });
                (PayloadType::MF, seal.len(), serialized_seals)
            }
            Attachment::AttachedSignatures(sigs) => {
                let serialized_sigs = sigs
                    .iter()
                    .fold("".into(), |acc, sig| [acc, sig.to_str()].join(""));
                (PayloadType::MA, sigs.len(), serialized_sigs)
            }
            Attachment::ReceiptCouplets(couplets) => {
                let packed_couplets = couplets.iter().fold("".into(), |acc, (bp, sp)| {
                    [acc, bp.to_str(), sp.to_str()].join("")
                });

                (PayloadType::MC, couplets.len(), packed_couplets)
            }
        };
        Ok([
            payload_type.adjust_with_num(att_len as u16),
            serialized_attachment,
        ]
        .join("").as_bytes().to_vec())
    
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