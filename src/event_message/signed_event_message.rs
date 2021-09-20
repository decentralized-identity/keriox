use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize, ser::SerializeStruct};
use std::cmp::Ordering;

use crate::{derivation::attached_signature_code::{get_sig_count, num_to_b64}, error::Error, event::sections::seal::EventSeal, prefix::{AttachedSignaturePrefix, BasicPrefix, Prefix, SelfSigningPrefix, attached_seal::AttachedEventSeal}, state::{EventSemantics, IdentifierState}};

use super::{EventMessage, payload_size::PayloadType};
use super::serializer::to_string;

// KERI serializer should be used to serialize this
#[derive(Debug, Clone, Deserialize)]
pub struct SignedEventMessage {
    pub event_message: EventMessage,
    #[serde(skip_serializing)]
    pub payload_type: PayloadType, 
    #[serde(skip_serializing)]
    pub signatures: Vec<AttachedSignaturePrefix>,
}

impl Serialize for SignedEventMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        // if JSON - we pack qb64 KERI
        if serializer.is_human_readable() {
            let mut em = serializer.serialize_struct("EventMessage", 2)?;
            em.serialize_field("", &self.event_message)?;
            let str_sigs = &self.signatures.iter().fold(String::default(), |accum, sig| accum + &sig.to_str());
            let code = self.calc_master_code(&str_sigs[..1]);
                // .map_err(|e| serde::ser::Error::custom(&e.to_string()))?;
            em.serialize_field("-" , &format!("{}{}", Box::leak(code.into_boxed_str()), str_sigs))?;
            em.end()
        // . else - we pack as it is for DB / CBOR purpose
        } else {
            let mut em = serializer.serialize_struct("SignedEventMessage", 3)?;
            em.serialize_field("event_message", &self.event_message)?;
            em.serialize_field("payload_type", &self.payload_type)?;
            em.serialize_field("signatures", &self.signatures)?;
            em.end()
        }
    }
}

impl PartialEq for SignedEventMessage {
    fn eq(&self, other: &Self) -> bool {
        self.event_message == other.event_message
        && self.signatures == other.signatures
    }
}

#[derive(Serialize, Deserialize)]
pub struct TimestampedSignedEventMessage {
    pub timestamp: DateTime<Local>,
    pub signed_event_message: SignedEventMessage,
}

impl TimestampedSignedEventMessage {
    pub fn new(event: SignedEventMessage) -> Self {
        Self {
            timestamp: Local::now(),
            signed_event_message: event,
        }
    }
}

impl From<TimestampedSignedEventMessage> for SignedEventMessage {
    fn from(event: TimestampedSignedEventMessage) -> SignedEventMessage {
        event.signed_event_message
    }
}

impl From<SignedEventMessage> for TimestampedSignedEventMessage {
    fn from(event: SignedEventMessage) -> TimestampedSignedEventMessage {
        TimestampedSignedEventMessage::new(event)
    }
}

impl From<&SignedEventMessage> for TimestampedSignedEventMessage {
    fn from(event: &SignedEventMessage) -> TimestampedSignedEventMessage {
        TimestampedSignedEventMessage::new(event.clone())
    }
}

impl PartialEq for TimestampedSignedEventMessage {
    fn eq(&self, other: &Self) -> bool {
        self.signed_event_message == other.signed_event_message
    }
}

impl PartialOrd for TimestampedSignedEventMessage {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(
            match self.signed_event_message.event_message.event.sn == other.signed_event_message.event_message.event.sn {
                true => Ordering::Equal,
                false => {
                    match self.signed_event_message.event_message.event.sn > other.signed_event_message.event_message.event.sn {
                        true => Ordering::Greater,
                        false => Ordering::Less,
                    }
                }
            },
        )
    }
}

impl Ord for TimestampedSignedEventMessage {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.signed_event_message.event_message.event.sn == other.signed_event_message.event_message.event.sn {
            true => Ordering::Equal,
            false => match self.signed_event_message.event_message.event.sn > other.signed_event_message.event_message.event.sn {
                true => Ordering::Greater,
                false => Ordering::Less,
            },
        }
    }
}

impl Eq for TimestampedSignedEventMessage {}

impl SignedEventMessage {
    pub fn new(message: &EventMessage, payload_type: PayloadType, sigs: Vec<AttachedSignaturePrefix>) -> Self {
        Self {
            event_message: message.clone(),
            payload_type,
            signatures: sigs,
        }
    }

    pub fn calc_master_code(&self, derivation: &str) -> String {
        format!("{}{}{}", 
            &self.payload_type.to_string(),
            derivation,
            num_to_b64(self.signatures.len() as u16))
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        Ok(to_string(&self)?.as_bytes().to_vec())
    }
}

impl EventSemantics for SignedEventMessage {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        self.event_message.apply_to(state)
    }
}

/// Signed Transferrable Receipt
///
/// Event Receipt which is suitable for creation by Transferable
/// Identifiers. Provides both the signatures and a commitment to
/// the latest establishment event of the receipt creator.
/// Mostly intended for use by Validators
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedTransferableReceipt {
    pub body: EventMessage,
    pub validator_seal: AttachedEventSeal,
    pub signatures: Vec<AttachedSignaturePrefix>,
}

impl SignedTransferableReceipt {
    pub fn new(
        message: &EventMessage,
        event_seal: EventSeal,
        sigs: Vec<AttachedSignaturePrefix>,
    ) -> Self {
        Self {
            body: message.clone(),
            validator_seal: AttachedEventSeal::new(event_seal),
            signatures: sigs,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        Ok([
            self.body.serialize()?,
            self.validator_seal.serialize()?,
            get_sig_count(self.signatures.len() as u16)
                .as_bytes()
                .to_vec(),
            self.signatures
                .iter()
                .map(|sig| sig.to_str().as_bytes().to_vec())
                .fold(vec![], |acc, next| [acc, next].concat()),
        ]
        .concat())
    }
}

/// Signed Non-Transferrable Receipt
///
/// A receipt created by an Identifier of a non-transferrable type.
/// Mostly intended for use by Witnesses.
/// NOTE: This receipt has a unique structure to it's appended
/// signatures
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedNontransferableReceipt {
    pub body: EventMessage,
    pub couplets: Vec<(BasicPrefix, SelfSigningPrefix)>,
}

impl SignedNontransferableReceipt {
    pub fn new(
        message: &EventMessage,
        couplets: Vec<(BasicPrefix, SelfSigningPrefix)>,
    ) -> Self {
        Self {
            body: message.clone(),
            couplets
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        Ok(
            [
                self.body.serialize()?,
                get_sig_count(self.couplets.len() as u16)
                    .as_bytes()
                    .to_vec(),
                self.couplets
                    .iter()
                    .map(|(_, sp)| sp.to_str().as_bytes().to_vec())
                    .fold(vec!(), |acc, next| [acc, next].concat()),
            ].concat()
        )
    }
}
