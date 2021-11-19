use std::convert::TryFrom;
use serde::Deserialize;

use crate::event::sections::seal::{EventSeal, SourceSeal};
use crate::prefix::{AttachedSignaturePrefix, BasicPrefix, SelfSigningPrefix};
use crate::{error::Error, event::event_data::EventData};

use super::signed_event_message::SignedEventMessage;
use super::{
    signed_event_message::{SignedNontransferableReceipt, SignedTransferableReceipt},
    EventMessage
};

// Do we need raw?
// #[derive(Clone, Debug, PartialEq)]
// pub struct DeserializedEvent<'a> {
//     pub event_message: EventMessage,
//     pub raw: &'a [u8],
// }

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub enum Attachment {
    SealSourceCouplets(Vec<SourceSeal>),
    AttachedEventSeal(Vec<EventSeal>),
    AttachedSignatures(Vec<AttachedSignaturePrefix>),
    ReceiptCouplets(Vec<(BasicPrefix, SelfSigningPrefix)>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeserializedSignedEvent {
    pub deserialized_event: EventMessage,
    pub attachments: Vec<Attachment>,
}

#[derive(Clone, Debug)]
pub enum Deserialized {
    // Event verification requires raw bytes, so use DesrializedSignedEvent
    Event(SignedEventMessage),
    // Rct's have an alternative appended signature structure,
    // use SignedNontransferableReceipt and SignedTransferableReceipt
    NontransferableRct(SignedNontransferableReceipt),
    TransferableRct(SignedTransferableReceipt),
}

// There is no bijection between DeserializedSignedEvent and SignedEventMessage.
// There exists DeserializedSignedEvent which can't be converted into
// SignedEventMessage, for example any receipt. It depends on attachments.

// // FIXME: detect payload type
// impl From<DeserializedSignedEvent> for SignedEventMessage {
//     fn from(de: DeserializedSignedEvent) -> SignedEventMessage {
//         SignedEventMessage::new(
//             &de.deserialized_event,
//             PayloadType::MA,
//             de.signatures,
//             de.attachments,
//         )
//     }
// }

impl TryFrom<DeserializedSignedEvent> for Deserialized {
    type Error = Error;

    fn try_from(value: DeserializedSignedEvent) -> Result<Self, Self::Error> {
        signed_message(value)
    }
}

pub fn signed_message<'a>(mut des: DeserializedSignedEvent) -> Result<Deserialized, Error> {
    match des.deserialized_event.event.event_data {
        EventData::Rct(_) => {
            let att = des.attachments.pop().unwrap();
            match att {
                // Should be nontransferable receipt
                Attachment::ReceiptCouplets(couplets) => 
                Ok(
                    Deserialized::NontransferableRct(SignedNontransferableReceipt {
                        body: des.deserialized_event,
                        couplets,
                    })
                ),
                Attachment::AttachedEventSeal(_) | Attachment::AttachedSignatures(_) => {
                    // Should be transferable receipt
                    let second_att = des.attachments.pop().unwrap();

                    let (seals, sigs) = match (att, second_att) {
                        (
                            Attachment::AttachedEventSeal(seals),
                            Attachment::AttachedSignatures(sigs),
                        ) => Ok((seals, sigs)),
                        (
                            Attachment::AttachedSignatures(sigs),
                            Attachment::AttachedEventSeal(seals),
                        ) => Ok((seals, sigs)),
                        _ => {
                            // improper attachments
                            Err(Error::SemanticError("Improper attachment".into()))
                        }
                    }?;

                    Ok(
                        Deserialized::TransferableRct(SignedTransferableReceipt::new(
                            &des.deserialized_event,
                            // TODO what if more than one?
                            seals
                                .last()
                                .ok_or(Error::SemanticError("More than one seal".into()))?
                                .to_owned(),
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
            let (att1, att2) = (des.attachments.pop().unwrap(), des.attachments.pop().unwrap());

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
            Ok(
                Deserialized::Event(
                    SignedEventMessage::new(&des.deserialized_event, sigs, Some(vec![Attachment::SealSourceCouplets(seals)]))
                ),
            )
        }
        _ => {
            let sigs = des.attachments.first().unwrap();
            if let Attachment::AttachedSignatures(sigs) = sigs {
                Ok(
                    Deserialized::Event(
                    SignedEventMessage::new(&des.deserialized_event, sigs.to_vec(), None)
                ))
            } else {
                // Improper attachment type
                Err(Error::SemanticError("Improper attachment type".into()))
            }
        }
    }
}

// pub fn signed_event_stream_validate(s: &[u8]) -> nom::IResult<&[u8], IdentifierState> {
//     let (rest, id) = fold_many1(
//         signed_message,
//         Ok(IdentifierState::default()),
//         |acc, next| match next {
//             Deserialized::Event(e) => {
//                 let new_state = acc?
//                     .apply(&e.deserialized_event)
//                     .map_err(|_| nom::Err::Error((s, ErrorKind::Verify)))?;
//                 if new_state
//                     .current
//                     .verify(&e.deserialized_event.serialize().unwrap(), &e.signatures)
//                     .map_err(|_| nom::Err::Error((s, ErrorKind::Verify)))?
//                 {
//                     Ok(new_state)
//                 } else {
//                     Err(nom::Err::Error((s, ErrorKind::Verify)))
//                 }
//             }
//             // TODO this probably should not just skip non-events
//             _ => acc,
//         },
//     )(s)?;

//     Ok((rest, id?))
// }

#[test]
fn test_stream1() {
    use crate::event_parsing;
    // taken from KERIPY: tests/core/test_eventing.py::test_kevery#1998
    let stream = br#"{"v":"KERI10JSON0000ed_","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","bt":"0","b":[],"c":[],"a":[]}-AABAAmagesCSY8QhYYHCJXEWpsGD62qoLt2uyT0_Mq5lZPR88JyS5UrwFKFdcjPqyKc_SKaKDJhkGWCk07k_kVkjyCA"#;

    let parsed = event_parsing::signed_message(stream).unwrap().1;
    let msg= signed_message(parsed).unwrap();
    assert!(matches!(msg, Deserialized::Event(_)));

    match msg {
        Deserialized::Event(signed_event) => {
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

    let parsed = event_parsing::signed_message(stream).unwrap().1;
    let msg = signed_message(parsed);
    assert!(msg.is_ok());
    assert!(matches!(msg, Ok(Deserialized::Event(_))));

    match msg.unwrap() {
        Deserialized::Event(signed_event) => {
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
    use crate::event_parsing;
    let trans_receipt_event = br#"{"v":"KERI10JSON000091_","i":"E7WIS0e4Tx1PcQW5Um5s3Mb8uPSzsyPODhByXzgvmAdQ","s":"0","t":"rct","d":"ErDNDBG7x2xYAH2i4AOnhVe44RS3lC1mRRdkyolFFHJk"}-FABENlofRlu2VPul-tjDObk6bTia2deG6NMqeFmsXhAgFvA0AAAAAAAAAAAAAAAAAAAAAAAE_MT0wsz-_ju_DVK_SaMaZT9ZE7pP4auQYeo2PDaw9FI-AABAA0Q7bqPvenjWXo_YIikMBKOg-pghLKwBi1Plm0PEqdv67L1_c6dq9bll7OFnoLp0a74Nw1cBGdjIPcu-yAllHAw"#;
    let parsed_trans_receipt = event_parsing::signed_message(trans_receipt_event).unwrap().1;
    let msg = signed_message(parsed_trans_receipt);
    assert!(matches!(msg, Ok(Deserialized::TransferableRct(_))));
    assert!(msg.is_ok());

    // Taken from keripy/core/test_witness.py
    let nontrans_rcp = br#"{"v":"KERI10JSON000091_","i":"EpU9D_puIW_QhgOf3WKUy-gXQnXeTQcJCO_Igcxi1YBg","s":"0","t":"rct","d":"EIt0xQQf-o-9E1B9VTDHiicQzVWk1CptvnewcnuhSd0M"}-CABB389hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd680BCZrTPLvG7sNaxtV8ZGdIHABFHCZ9FlnG6b4J6a9GcyzJIJOjuGNphW2zyC_WWU6CGMG7V52UeJxPqLpaYdP7Cg"#;
    let parsed_nontrans_receipt = event_parsing::signed_message(nontrans_rcp).unwrap().1;
    let msg = signed_message(parsed_nontrans_receipt);
    assert!(msg.is_ok());
    assert!(matches!(msg, Ok(Deserialized::NontransferableRct(_))));

    // Nontrans receipt with alternative attachment with -B payload type. Not implemented yet.
    // let witness_receipts = r#"{"v":"KERI10JSON000091_","i":"EpU9D_puIW_QhgOf3WKUy-gXQnXeTQcJCO_Igcxi1YBg","s":"0","t":"rct","d":"EIt0xQQf-o-9E1B9VTDHiicQzVWk1CptvnewcnuhSd0M"}-BADAACZrTPLvG7sNaxtV8ZGdIHABFHCZ9FlnG6b4J6a9GcyzJIJOjuGNphW2zyC_WWU6CGMG7V52UeJxPqLpaYdP7CgAB8npsG58rX1ex73gaGe-jvRnw58RQGsDLzoSXaGn-kHRRNu6Kb44zXDtMnx-_8CjnHqskvDbz6pbEbed3JTOnCQACM4bMcLjcDtD0fmLOGDx2oxBloc2FujbyllA7GuPLm-RQbyPPQr70_Y7DXzlWgs8gaYotUATeR-dj1ru9qFwADA"#;
    // let msg = signed_message(witness_receipts.as_bytes());
    // assert!(msg.is_ok());
}
