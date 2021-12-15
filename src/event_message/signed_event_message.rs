use chrono::{DateTime, Local};
use serde::{ser::SerializeStruct, Deserialize, Serialize};
use std::cmp::Ordering;

use crate::{error::Error, event::{Event, sections::seal::{EventSeal, SourceSeal}}, event_parsing::Attachment, prefix::{AttachedSignaturePrefix, BasicPrefix, SelfSigningPrefix}, state::{EventSemantics, IdentifierState}};
use super::serializer::to_string;
use super::EventMessage;

#[cfg(feature = "query")]
use crate::query::reply::SignedReply;

#[derive(Clone, Debug, PartialEq)]
pub enum Message {
    Event(SignedEventMessage),
    // Rct's have an alternative appended signature structure,
    // use SignedNontransferableReceipt and SignedTransferableReceipt
    NontransferableRct(SignedNontransferableReceipt),
    TransferableRct(SignedTransferableReceipt),
    #[cfg(feature = "query")]
    KeyStateNotice(SignedReply),
}

// KERI serializer should be used to serialize this
#[derive(Debug, Clone, Deserialize)]
pub struct SignedEventMessage {
    pub event_message: EventMessage<Event>,
    #[serde(skip_serializing)]
    pub signatures: Vec<AttachedSignaturePrefix>,
    #[serde(skip_serializing)]
    pub delegator_seal: Option<SourceSeal>,
}

impl Serialize for SignedEventMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // if JSON - we pack qb64 KERI
        if serializer.is_human_readable() {
            let mut em = serializer.serialize_struct("EventMessage", 2)?;
            em.serialize_field("", &self.event_message)?;
            let att_sigs = Attachment::AttachedSignatures(self.signatures.clone());
            em.serialize_field("-", &att_sigs.to_cesr())?;
            em.end()
        // . else - we pack as it is for DB / CBOR purpose
        } else {
            let mut em = serializer.serialize_struct("SignedEventMessage", 2)?;
            em.serialize_field("event_message", &self.event_message)?;
            em.serialize_field("signatures", &self.signatures)?;
            em.end()
        }
    }
}

impl PartialEq for SignedEventMessage {
    fn eq(&self, other: &Self) -> bool {
        self.event_message == other.event_message && self.signatures == other.signatures
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
            match self.signed_event_message.event_message.event.sn
                == other.signed_event_message.event_message.event.sn
            {
                true => Ordering::Equal,
                false => {
                    match self.signed_event_message.event_message.event.sn
                        > other.signed_event_message.event_message.event.sn
                    {
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
        match self.signed_event_message.event_message.event.sn
            == other.signed_event_message.event_message.event.sn
        {
            true => Ordering::Equal,
            false => match self.signed_event_message.event_message.event.sn
                > other.signed_event_message.event_message.event.sn
            {
                true => Ordering::Greater,
                false => Ordering::Less,
            },
        }
    }
}

impl Eq for TimestampedSignedEventMessage {}

impl SignedEventMessage {
    pub fn new(
        message: &EventMessage<Event>,
        sigs: Vec<AttachedSignaturePrefix>,
        delegator_seal: Option<SourceSeal>,
    ) -> Self {
        Self {
            event_message: message.clone(),
            signatures: sigs,
            delegator_seal
        }
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
    pub body: EventMessage<Event>,
    pub validator_seal: EventSeal,
    pub signatures: Vec<AttachedSignaturePrefix>,
}

impl SignedTransferableReceipt {
    pub fn new(
        message: &EventMessage<Event>,
        event_seal: EventSeal,
        sigs: Vec<AttachedSignaturePrefix>,
    ) -> Self {
        Self {
            body: message.clone(),
            validator_seal: event_seal,
            signatures: sigs,
        }
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
    pub body: EventMessage<Event>,
    pub couplets: Vec<(BasicPrefix, SelfSigningPrefix)>,
}

impl SignedNontransferableReceipt {
    pub fn new(message: &EventMessage<Event>, couplets: Vec<(BasicPrefix, SelfSigningPrefix)>) -> Self {
        Self {
            body: message.clone(),
            couplets,
        }
    }
}