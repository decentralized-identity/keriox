use std::convert::TryFrom;
use base64::URL_SAFE_NO_PAD;
use serde::Deserialize;

use crate::event::receipt::Receipt;
use crate::event::EventMessage;
use crate::event::sections::seal::{EventSeal, SourceSeal};
use crate::event_message::KeyEvent;
use crate::event_message::signed_event_message::{Message, SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt};
use crate::event_parsing::payload_size::PayloadType;
use crate::prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, Prefix, SelfSigningPrefix};

#[cfg(feature = "query")]
use crate::query::{query::QueryEvent, reply::{ReplyEvent, SignedReply}};
use crate::{error::Error, event::event_data::EventData};

pub mod attachment;
pub mod payload_size;
pub mod prefix;
pub mod message;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub enum Attachment {
    // Count codes
    SealSourceCouplets(Vec<SourceSeal>),
    AttachedSignatures(Vec<AttachedSignaturePrefix>),
    ReceiptCouplets(Vec<(BasicPrefix, SelfSigningPrefix)>),
    // Group codes
    SealSignaturesGroups(Vec<(EventSeal, Vec<AttachedSignaturePrefix>)>),
    // List of signatures made using keys from last establishment event od identifier of prefix 
    LastEstSignaturesGroups(Vec<(IdentifierPrefix, Vec<AttachedSignaturePrefix>)>),
    // Frame codes
    Frame(Vec<Attachment>),
}

impl Attachment {
    pub fn to_cesr(&self) -> String {
         let (payload_type, att_len, serialized_attachment) = match self {
            Attachment::SealSourceCouplets(sources) => {
                let serialzied_sources = sources
                    .iter()
                    .fold("".into(), |acc, s| [acc, Self::pack_sn(s.sn), s.digest.to_str()].join(""));

                (PayloadType::MG, sources.len(), serialzied_sources)
            }
            Attachment::SealSignaturesGroups(seals_signatures) => {
                let serialized_seals = seals_signatures.iter().fold("".into(), |acc, (seal, sigs)| {
                    [
                        acc,
                        seal.prefix.to_str(),
                        Self::pack_sn(seal.sn),
                        seal.event_digest.to_str(),
                        Attachment::AttachedSignatures(sigs.to_vec()).to_cesr(),
                    ]
                    .join("")
                });
                (PayloadType::MF, seals_signatures.len(), serialized_seals)
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
            Attachment::LastEstSignaturesGroups(signers) => {
                let packed_signers = signers
                    .iter()
                    .fold("".to_string(), |acc, (signer, sigs)| {
                        [
                            acc, 
                            signer.to_str(), 
                            Attachment::AttachedSignatures(sigs.clone()).to_cesr()
                        ].concat()
                });
                (PayloadType::MH, signers.len(), packed_signers)
            },
            Attachment::Frame(att) => {
                let packed_attachments = att
                    .iter()
                    .fold("".to_string(), |acc, att| 
                    [acc, att.to_cesr()].concat()
                );
                (PayloadType::MV, packed_attachments.len(), packed_attachments)
            },
        };
        [
            payload_type.adjust_with_num(att_len as u16),
            serialized_attachment,
        ]
        .join("")
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
    }

#[derive(Clone, Debug, PartialEq)]
pub struct SignedEventData {
    pub deserialized_event: EventType,
    pub attachments: Vec<Attachment>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum EventType {
    KeyEvent(EventMessage<KeyEvent>),
    Receipt(EventMessage<Receipt>),
    #[cfg(feature = "query")]
    Qry(EventMessage<QueryEvent>),
    #[cfg(feature = "query")]
    Rpy(EventMessage<ReplyEvent>),
}

impl EventType {
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        match self {
            EventType::KeyEvent(event) => event.serialize(),
            EventType::Receipt(rcp) => rcp.serialize(),
            #[cfg(feature = "query")]
            EventType::Qry(qry) => qry.serialize(),
            #[cfg(feature = "query")]
            EventType::Rpy(rpy) => rpy.serialize(),
        }
    }
}

impl SignedEventData {
    pub fn to_cesr(&self) -> Result<Vec<u8>, Error> {
        let attachments = self.attachments
            .iter()
            .fold(String::default(), |acc, att| [acc, att.to_cesr()].concat())
            .as_bytes().to_vec();
        Ok([
            self.deserialized_event.serialize()?,
            attachments,
        ]
        .concat())
    }    
}

impl From<&SignedEventMessage> for SignedEventData {
    fn from(ev: &SignedEventMessage) -> Self {
        let attachments = match ev.delegator_seal.clone() {
            Some(delegator_seal) => 
                [
                    Attachment::SealSourceCouplets(vec![delegator_seal]),
                    Attachment::AttachedSignatures(ev.signatures.clone()) 
                ].into(),
            None => [Attachment::AttachedSignatures(ev.signatures.clone())].into(),
        }; 
        
        SignedEventData { 
            deserialized_event: EventType::KeyEvent(ev.event_message.clone()), 
            attachments
        }
    }
    
}

impl From<SignedNontransferableReceipt> for SignedEventData {
    fn from(rcp: SignedNontransferableReceipt) -> SignedEventData {
        let attachments = [Attachment::ReceiptCouplets(rcp.couplets)].into();
        SignedEventData { 
            deserialized_event: EventType::Receipt(rcp.body), 
            attachments 
        }
    }
}

impl From<SignedTransferableReceipt> for SignedEventData {
    fn from(rcp: SignedTransferableReceipt) -> SignedEventData {
        let attachments = [
                Attachment::SealSignaturesGroups(vec![(rcp.validator_seal, rcp.signatures)]), 
            ].into();
        SignedEventData { 
            deserialized_event: EventType::Receipt(rcp.body), 
            attachments 
        }
    }
}

#[cfg(feature = "query")]
impl From<SignedReply> for SignedEventData {
    fn from(ev: SignedReply) -> Self {
        use crate::event_message::signature::Signature;
        let attachments = vec![
            match ev.signature.clone() {
                Signature::Transferable(seal, sig) => 
                    Attachment::SealSignaturesGroups(vec![(seal, sig)]),
                Signature::NonTransferable(pref, sig) => 
                    Attachment::ReceiptCouplets(vec![(pref, sig)]),
        }]; 
        
        SignedEventData { 
            deserialized_event: EventType::Rpy(ev.reply), 
            attachments
        }
    }
    
}

impl TryFrom<SignedEventData> for Message {
    type Error = Error;

    fn try_from(value: SignedEventData) -> Result<Self, Self::Error> {
        match value.deserialized_event {
            EventType::KeyEvent(ev) => signed_key_event(ev, value.attachments),
            EventType::Receipt(rct) => signed_receipt(rct, value.attachments),
            #[cfg(feature = "query")]
            EventType::Qry(qry) => signed_query(qry, value.attachments),
            #[cfg(feature = "query")]
            EventType::Rpy(rpy) => signed_reply(rpy, value.attachments),
        }
    }
}

#[cfg(feature = "query")]
fn signed_reply(rpy: EventMessage<ReplyEvent>, mut attachments: Vec<Attachment>) -> Result<Message, Error> {
    match attachments.pop().ok_or_else(|| Error::SemanticError("Missing attachment".into()))? {
        Attachment::ReceiptCouplets(couplets) => {
        let signer = couplets[0].0.clone();
        let signature = couplets[0].1.clone();
        Ok(
            Message::KeyStateNotice(SignedReply::new_nontrans(rpy, signer, signature))
        )},
        Attachment::SealSignaturesGroups(data) => {
            let (seal, sigs) = 
                // TODO what if more than one?
                data
                    .last()
                    .ok_or_else(|| Error::SemanticError("More than one seal".into()))?
                    .to_owned();
            Ok(
            Message::KeyStateNotice(SignedReply::new_trans(rpy, seal, sigs))
            ) 
        }
        _ => {
            // Improper payload type
            Err(Error::SemanticError("Improper payload type".into()))
        }
    }
}

#[cfg(feature = "query")]
fn signed_query(qry: EventMessage<QueryEvent>, mut attachments: Vec<Attachment>) -> Result<Message, Error> {
    use crate::query::query::SignedQuery;

    match attachments.pop().ok_or_else(|| Error::SemanticError("Missing attachment".into()))? {
        Attachment::LastEstSignaturesGroups(groups) => {
            let (signer, signatures) = groups[0].clone();
            Ok(Message::Query(SignedQuery { envelope: qry, signer, signatures }))
        },
        Attachment::Frame(atts) => {
            signed_query(qry, atts)
        },
        _ => {
            // Improper payload type
            Err(Error::SemanticError("Improper attachments for query message".into()))
        }
    }
}


fn signed_key_event(event_message: EventMessage<KeyEvent>, mut attachments: Vec<Attachment>) -> Result<Message, Error> {
    match event_message.event.get_event_data() {
        EventData::Dip(_) | EventData::Drt(_) => {
            let (att1, att2) = (
                attachments.pop().ok_or_else(|| Error::SemanticError("Missing attachment".into()))?, 
                attachments.pop().ok_or_else(|| Error::SemanticError("Missing attachment".into()))?,
            );

            let (seals, sigs) = match (att1, att2) {
                (Attachment::SealSourceCouplets(seals), Attachment::AttachedSignatures(sigs)) => {
                    Ok((seals, sigs))
                }
                (Attachment::AttachedSignatures(sigs), Attachment::SealSourceCouplets(seals)) => {
                    Ok((seals, sigs))
                }
                _ => {
                    // Improper attachment type
                    Err(Error::SemanticError("Improper attachment type".into()))
                }
            }?;
            let delegator_seal = match seals.len() {
                0 => Err(Error::SemanticError("Missing delegator seal".into())),
                1 => Ok(seals.first().cloned()),
                _ => Err(Error::SemanticError("Too many seals".into())),
            };
            
            Ok(
                Message::Event(
                    SignedEventMessage::new(&event_message, sigs, delegator_seal?)
                ),
            )
        }
        _ => {
            let sigs = attachments.first().cloned().ok_or_else(|| Error::SemanticError("Missing attachment".into()))?;
            if let Attachment::AttachedSignatures(sigs) = sigs {
                Ok(
                    Message::Event(
                    SignedEventMessage::new(&event_message, sigs.to_vec(), None)
                ))
            } else {
                // Improper attachment type
                Err(Error::SemanticError("Improper attachment type".into()))
            }
        }
    }
}

fn signed_receipt(event_message: EventMessage<Receipt>, mut attachments: Vec<Attachment>) -> Result<Message, Error> {
    let att = attachments.pop().ok_or_else(|| Error::SemanticError("Missing attachment".into()))?;
    match att {
        // Should be nontransferable receipt
        Attachment::ReceiptCouplets(couplets) => 
        Ok(
            Message::NontransferableRct(SignedNontransferableReceipt {
                body: event_message,
                couplets,
            })
        ),
        Attachment::SealSignaturesGroups(data) => {
            // Should be transferable receipt
            let (seal, sigs) = 
                // TODO what if more than one?
                data
                    .last()
                    .ok_or_else(|| Error::SemanticError("More than one seal".into()))?
                    .to_owned();
            Ok(
                Message::TransferableRct(SignedTransferableReceipt::new(
                    event_message,
                    seal,
                    sigs,
                )),
            )
        }
        _ => {
            // Improper payload type
            Err(Error::SemanticError("Improper payload type".into()))
        }
    }
}

#[test]
fn test_stream1() {
    use crate::event_parsing;
    // taken from KERIPY: tests/core/test_kevery.py#62
    let stream = br#"{"v":"KERI10JSON000120_","t":"icp","d":"EG4EuTsxPiRM7soX10XXzNsS1KqXKUp8xsQ-kW_tWHoI","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"0","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","bt":"0","b":[],"c":[],"a":[]}-AABAA0aSisI4ZZTH_6JCqsvAsEpuf_Jq6bDbvPWj_eCDnAGbSARqYHipNs-9W7MHnwnMfIXwLpcoJkKGrQ-SiaklhAw"#;

    let parsed = event_parsing::message::signed_message(stream).unwrap().1;
    let msg = Message::try_from(parsed).unwrap();
    assert!(matches!(msg, Message::Event(_)));

    match msg {
        Message::Event(signed_event) => {
            assert_eq!(
                signed_event.event_message.serialize().unwrap().len(),
                signed_event
                    .event_message
                    .serialization_info
                    .size
            );

            let serialized_again = signed_event.serialize();
            assert!(serialized_again.is_ok());
            let stringified = String::from_utf8(serialized_again.unwrap()).unwrap();
            assert_eq!(stream, stringified.as_bytes())
        }
        _ => assert!(false),
    }
}

#[test]
fn test_stream2() {
    use crate::event_parsing;
    // taken from KERIPY: tests/core/test_eventing.py::test_multisig_digprefix#2256
    let stream = br#"{"v":"KERI10JSON00017e_","t":"icp","d":"ELYk-z-SuTIeDncLr6GhwVUKnv3n3F1bF18qkXNd2bpk","i":"ELYk-z-SuTIeDncLr6GhwVUKnv3n3F1bF18qkXNd2bpk","s":"0","kt":"2","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"n":"E9izzBkXX76sqt0N-tfLzJeRqj0W56p4pDQ_ZqNCDpyw","bt":"0","b":[],"c":[],"a":[]}-AADAA39j08U7pcU66OPKsaPExhBuHsL5rO1Pjq5zMgt_X6jRbezevis6YBUg074ZNKAGdUwHLqvPX_kse4buuuSUpAQABphobpuQEZ6EhKLhBuwgJmIQu80ZUV1GhBL0Ht47Hsl1rJiMwE2yW7-yi8k3idw2ahlpgdd9ka9QOP9yQmMWGAQACM7yfK1b86p1H62gonh1C7MECDCFBkoH0NZRjHKAEHebvd2_LLz6cpCaqKWDhbM2Rq01f9pgyDTFNLJMxkC-fAQ"#;
    // let stream = br#"{"v":"KERI10JSON00014b_","i":"EsiHneigxgDopAidk_dmHuiUJR3kAaeqpgOAj9ZZd4q8","s":"0","t":"icp","kt":"2","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"n":"E9izzBkXX76sqt0N-tfLzJeRqj0W56p4pDQ_ZqNCDpyw","bt":"0","b":[],"c":[],"a":[]}-AADAAhcaP-l0DkIKlJ87iIVcDx-m0iKPdSArEu63b-2cSEn9wXVGNpWw9nfwxodQ9G8J3q_Pm-AWfDwZGD9fobWuHBAAB6mz7zP0xFNBEBfSKG4mjpPbeOXktaIyX8mfsEa1A3Psf7eKxSrJ5Woj3iUB2AhhLg412-zkk795qxsK2xfdxBAACj5wdW-EyUJNgW0LHePQcSFNxW3ZyPregL4H2FoOrsPxLa3MZx6xYTh6i7YRMGY50ezEjV81hkI1Yce75M_bPCQ"#;

    let parsed = event_parsing::message::signed_message(stream).unwrap().1;
    let msg = Message::try_from(parsed);
    assert!(msg.is_ok());
    assert!(matches!(msg, Ok(Message::Event(_))));

    match msg.unwrap() {
        Message::Event(signed_event) => {
            assert_eq!(
                signed_event.event_message.serialize().unwrap().len(),
                signed_event
                    .event_message
                    .serialization_info
                    .size
            );

            let serialized_again = signed_event.serialize();
            assert!(serialized_again.is_ok());
            let stringified = String::from_utf8(serialized_again.unwrap()).unwrap();
            assert_eq!(stream, stringified.as_bytes())
        }
        _ => assert!(false),
    }

}

#[test]
fn test_deserialize_signed_receipt() {
    use crate::event_parsing::message::signed_message;
    // Taken from keripy/tests/core/test_eventing.py::test_direct_mode
    let trans_receipt_event = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EsZuhYAPBDnexP3SOl9YsGvWBrYkjYcRjomUYmCcLAYY","i":"EsZuhYAPBDnexP3SOl9YsGvWBrYkjYcRjomUYmCcLAYY","s":"0"}-FABE7pB5IKuaYh3aIWKxtexyYFhpSjDNTEGSQuxeJbWiylg0AAAAAAAAAAAAAAAAAAAAAAAE7pB5IKuaYh3aIWKxtexyYFhpSjDNTEGSQuxeJbWiylg-AABAAlIts3z2kNyis9l0Pfu54HhVN_yZHEV7NWIVoSTzl5IABelbY8xi7VRyW42ZJvBaaFTGtiqwMOywloVNpG_ZHAQ"#;
    let parsed_trans_receipt = signed_message(trans_receipt_event).unwrap().1;
    let msg = Message::try_from(parsed_trans_receipt); 
    assert!(matches!(msg, Ok(Message::TransferableRct(_))));
    assert!(msg.is_ok());

    // Taken from keripy/core/test_witness.py::test_nonindexed_witness_receipts
    let nontrans_rcp = br#"{"v":"KERI10JSON000091_","t":"rct","d":"E77aKmmdHtYKuJeBOYWRHbi8C6dYqzG-ESfdvlUAptlo","i":"EHz9RXAr9JiJn-3wkBvsUo1Qq3hvMQPaITxzcfJND8NM","s":"2"}-CABB389hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd680Bpx_cu_UoMtD0ES-bS9Luh-b2A_AYmM3PmVNfgFrFXls4IE39-_D14dS46NEMqCf0vQmqDcQmhY-UOpgoyFS2Bw"#;
    let parsed_nontrans_receipt = signed_message(nontrans_rcp).unwrap().1;
    let msg = Message::try_from(parsed_nontrans_receipt);
    assert!(msg.is_ok());
    assert!(matches!(msg, Ok(Message::NontransferableRct(_))));

    // Nontrans receipt with alternative attachment with -B payload type. Not implemented yet.
    // takien from keripy/tests/core/test_witness.py::test_indexed_witness_reply
    // let wintess_receipts = r#"{"v":"KERI10JSON000091_","t":"rct","d":"EHz9RXAr9JiJn-3wkBvsUo1Qq3hvMQPaITxzcfJND8NM","i":"EHz9RXAr9JiJn-3wkBvsUo1Qq3hvMQPaITxzcfJND8NM","s":"0"}-BADAAdgQkf11JTyF2WVA1Vji1ZhXD8di4AJsfro-sN_jURM1SUioeOleik7w8lkDldKtg0-Nr1X32V9Q8tk8RvBGxDgABZmkRun-qNliRA8WR2fIUnVeB8eFLF7aLFtn2hb31iW7wYSYafR0kT3fV_r1wNNdjm9dkBw-_2xsxThTGfO5UAwACRGJiRPFe4ClvpqZL3LHcEAeT396WVrYV10EaTdt0trINT8rPbz96deSFT32z3myNPVwLlNcq4FzIaQCooM2HDQ"#;
    // let msg = signed_message(witness_receipts.as_bytes());
    // assert!(msg.is_ok());
}
