use std::convert::TryFrom;
use base64::URL_SAFE_NO_PAD;
use serde::Deserialize;

use crate::event::{Event, EventMessage};
use crate::event::sections::seal::{EventSeal, SourceSeal};
use crate::event_message::signed_event_message::{Message, SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt};
use crate::event_parsing::payload_size::PayloadType;
use crate::prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, Prefix, SelfSigningPrefix};

#[cfg(feature = "query")]
use crate::query::Envelope;

use crate::query::query::QueryData;
use crate::query::reply::ReplyData;
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
    pub deserialized_event: Option<EventMessage<Event>>,
    #[cfg(feature = "query")]
    pub envelope: Option<QueryEvent>,
    pub attachments: Vec<Attachment>,
}

#[cfg(feature = "query")]
#[derive(Clone, Debug, PartialEq)]
pub enum QueryEvent {
    Qry(EventMessage<Envelope<QueryData>>),
    Rpy(EventMessage<Envelope<ReplyData>>),
}

impl SignedEventData {
    pub fn to_cesr(&self) -> Result<Vec<u8>, Error> {
        let attachments = self.attachments
            .iter()
            .fold(String::default(), |acc, att| [acc, att.to_cesr()].concat())
            .as_bytes().to_vec();
        Ok([
            self.deserialized_event.as_ref().unwrap().serialize()?,
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
            deserialized_event: Some(ev.event_message.clone()), 
            #[cfg(feature = "query")]
            envelope: None, 
            attachments
        }
    }
    
}

impl From<SignedNontransferableReceipt> for SignedEventData {
    fn from(rcp: SignedNontransferableReceipt) -> SignedEventData {
        let attachments = [Attachment::ReceiptCouplets(rcp.couplets)].into();
        SignedEventData { 
            deserialized_event: Some(rcp.body), 
            #[cfg(feature = "query")]
            envelope: None, 
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
            deserialized_event: Some(rcp.body), 
            #[cfg(feature = "query")]
            envelope: None, 
            attachments 
        }
    }
}

impl TryFrom<SignedEventData> for Message {
    type Error = Error;

    fn try_from(value: SignedEventData) -> Result<Self, Self::Error> {
        if value.deserialized_event.is_some() {
            signed_message(value)
        } else {
            #[cfg(feature = "query")]
            signed_reply(value)
        }
    }
}

#[cfg(feature = "query")]
fn signed_reply(mut des: SignedEventData) -> Result<Message, Error> {
    use crate::query::SignedReply;
    match des.envelope.unwrap() {
        QueryEvent::Qry(_) => todo!(),
        QueryEvent::Rpy(rpy) => {
            // let sr = SignedReply::new(des.envelope, );
            match des.attachments.pop().ok_or_else(|| Error::SemanticError("Missing attachment".into()))? {
                // Should be nontransferable receipt
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
        },
    }
}

fn signed_message(mut des: SignedEventData) -> Result<Message, Error> {
    match des.deserialized_event.clone().unwrap().event.event_data {
        EventData::Rct(_) => {
            let att = des.attachments.pop().ok_or_else(|| Error::SemanticError("Missing attachment".into()))?;
            match att {
                // Should be nontransferable receipt
                Attachment::ReceiptCouplets(couplets) => 
                Ok(
                    Message::NontransferableRct(SignedNontransferableReceipt {
                        body: des.deserialized_event.unwrap(),
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
                            &des.deserialized_event.unwrap(),
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
        EventData::Dip(_) | EventData::Drt(_) => {
            let (att1, att2) = (
                des.attachments.pop().ok_or_else(|| Error::SemanticError("Missing attachment".into()))?, 
                des.attachments.pop().ok_or_else(|| Error::SemanticError("Missing attachment".into()))?,
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
                    SignedEventMessage::new(&des.deserialized_event.unwrap(), sigs, delegator_seal?)
                ),
            )
        }
        _ => {
            let sigs = des.attachments.first().cloned().ok_or_else(|| Error::SemanticError("Missing attachment".into()))?;
            if let Attachment::AttachedSignatures(sigs) = sigs {
                Ok(
                    Message::Event(
                    SignedEventMessage::new(&des.deserialized_event.unwrap(), sigs.to_vec(), None)
                ))
            } else {
                // Improper attachment type
                Err(Error::SemanticError("Improper attachment type".into()))
            }
        }
    }
}

#[test]
fn test_stream1() {
    use crate::event_parsing;
    // taken from KERIPY: tests/core/test_eventing.py::test_kevery#1998
    let stream = br#"{"v":"KERI10JSON0000ed_","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","bt":"0","b":[],"c":[],"a":[]}-AABAAmagesCSY8QhYYHCJXEWpsGD62qoLt2uyT0_Mq5lZPR88JyS5UrwFKFdcjPqyKc_SKaKDJhkGWCk07k_kVkjyCA"#;

    let parsed = event_parsing::message::signed_message(stream).unwrap().1;
    let msg= signed_message(parsed).unwrap();
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
    // taken from KERIPY: tests/core/test_eventing.py::test_multisig_digprefix#2244
    let stream = br#"{"v":"KERI10JSON00014b_","i":"EsiHneigxgDopAidk_dmHuiUJR3kAaeqpgOAj9ZZd4q8","s":"0","t":"icp","kt":"2","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"n":"E9izzBkXX76sqt0N-tfLzJeRqj0W56p4pDQ_ZqNCDpyw","bt":"0","b":[],"c":[],"a":[]}-AADAAhcaP-l0DkIKlJ87iIVcDx-m0iKPdSArEu63b-2cSEn9wXVGNpWw9nfwxodQ9G8J3q_Pm-AWfDwZGD9fobWuHBAAB6mz7zP0xFNBEBfSKG4mjpPbeOXktaIyX8mfsEa1A3Psf7eKxSrJ5Woj3iUB2AhhLg412-zkk795qxsK2xfdxBAACj5wdW-EyUJNgW0LHePQcSFNxW3ZyPregL4H2FoOrsPxLa3MZx6xYTh6i7YRMGY50ezEjV81hkI1Yce75M_bPCQ"#;

    let parsed = event_parsing::message::signed_message(stream).unwrap().1;
    let msg = signed_message(parsed);
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
fn test_deserialize() {
    use crate::event_parsing::message::signed_message;
    let trans_receipt_event = br#"{"v":"KERI10JSON000091_","i":"E7WIS0e4Tx1PcQW5Um5s3Mb8uPSzsyPODhByXzgvmAdQ","s":"0","t":"rct","d":"ErDNDBG7x2xYAH2i4AOnhVe44RS3lC1mRRdkyolFFHJk"}-FABENlofRlu2VPul-tjDObk6bTia2deG6NMqeFmsXhAgFvA0AAAAAAAAAAAAAAAAAAAAAAAE_MT0wsz-_ju_DVK_SaMaZT9ZE7pP4auQYeo2PDaw9FI-AABAA0Q7bqPvenjWXo_YIikMBKOg-pghLKwBi1Plm0PEqdv67L1_c6dq9bll7OFnoLp0a74Nw1cBGdjIPcu-yAllHAw"#;
    let parsed_trans_receipt = signed_message(trans_receipt_event).unwrap().1;
    let msg = Message::try_from(parsed_trans_receipt); 
    assert!(matches!(msg, Ok(Message::TransferableRct(_))));
    assert!(msg.is_ok());

    // Taken from keripy/core/test_witness.py
    let nontrans_rcp = br#"{"v":"KERI10JSON000091_","i":"EpU9D_puIW_QhgOf3WKUy-gXQnXeTQcJCO_Igcxi1YBg","s":"0","t":"rct","d":"EIt0xQQf-o-9E1B9VTDHiicQzVWk1CptvnewcnuhSd0M"}-CABB389hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd680BCZrTPLvG7sNaxtV8ZGdIHABFHCZ9FlnG6b4J6a9GcyzJIJOjuGNphW2zyC_WWU6CGMG7V52UeJxPqLpaYdP7Cg"#;
    let parsed_nontrans_receipt = signed_message(nontrans_rcp).unwrap().1;
    let msg = Message::try_from(parsed_nontrans_receipt);
    assert!(msg.is_ok());
    assert!(matches!(msg, Ok(Message::NontransferableRct(_))));

    // Nontrans receipt with alternative attachment with -B payload type. Not implemented yet.
    // let witness_receipts = r#"{"v":"KERI10JSON000091_","i":"EpU9D_puIW_QhgOf3WKUy-gXQnXeTQcJCO_Igcxi1YBg","s":"0","t":"rct","d":"EIt0xQQf-o-9E1B9VTDHiicQzVWk1CptvnewcnuhSd0M"}-BADAACZrTPLvG7sNaxtV8ZGdIHABFHCZ9FlnG6b4J6a9GcyzJIJOjuGNphW2zyC_WWU6CGMG7V52UeJxPqLpaYdP7CgAB8npsG58rX1ex73gaGe-jvRnw58RQGsDLzoSXaGn-kHRRNu6Kb44zXDtMnx-_8CjnHqskvDbz6pbEbed3JTOnCQACM4bMcLjcDtD0fmLOGDx2oxBloc2FujbyllA7GuPLm-RQbyPPQr70_Y7DXzlWgs8gaYotUATeR-dj1ru9qFwADA"#;
    // let msg = signed_message(witness_receipts.as_bytes());
    // assert!(msg.is_ok());
}
