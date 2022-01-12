use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};

use crate::{
    derivation::self_addressing::SelfAddressing,
    error::Error,
    event::{sections::seal::EventSeal, EventMessage, SerializationFormats},
    event_message::{
        dummy_event::DummyEventMessage, signature::Signature, Digestible, SaidEvent, Typeable,
    },
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    state::IdentifierState,
};

use super::{key_state_notice::KeyStateNotice, Envelope, QueryError, Route};

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ReplyData {
    #[serde(rename = "a")]
    pub data: KeyStateNotice,
}

pub type ReplyEvent = SaidEvent<Envelope<ReplyData>>;
// pub type Reply = Envelope<ReplyData>;

impl ReplyEvent {
    pub fn new_reply(
        ksn: KeyStateNotice,
        route: Route,
        self_addressing: SelfAddressing,
        serialization: SerializationFormats,
    ) -> Result<EventMessage<ReplyEvent>, Error> {
        let rpy_data = ReplyData { data: ksn.clone() };
        let env = Envelope::new(route.clone(), rpy_data);
        env.to_message(serialization, &self_addressing)
    }

    pub fn get_timestamp(&self) -> DateTime<FixedOffset> {
        self.content.timestamp
    }

    pub fn get_prefix(&self) -> IdentifierPrefix {
        self.content.data.data.state.prefix.clone()
    }

    pub fn get_state(&self) -> IdentifierState {
        self.content.data.data.state.clone()
    }

    pub fn get_route(&self) -> Route {
        self.content.route.clone()
    }

    pub fn get_reply_data(&self) -> KeyStateNotice {
        self.content.data.data.clone()
    }
}

impl EventMessage<ReplyEvent> {
    pub fn check_digest(&self) -> Result<(), Error> {
        let dummy = DummyEventMessage::dummy_event(
            self.event.clone(),
            self.serialization_info.kind,
            &self.event.get_digest().unwrap().derivation,
        )?
        .serialize()?;
        self.event
            .get_digest()
            .unwrap_or_default()
            .verify_binding(&dummy)
            .then(|| ())
            .ok_or(QueryError::IncorrectDigest.into())
    }
}

impl Typeable for ReplyData {
    fn get_type(&self) -> Option<String> {
        Some("rpy".to_string())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SignedReply {
    pub reply: EventMessage<ReplyEvent>,
    pub signature: Signature,
}

impl SignedReply {
    pub fn new_nontrans(
        envelope: EventMessage<ReplyEvent>,
        signer: BasicPrefix,
        signature: SelfSigningPrefix,
    ) -> Self {
        let signature = Signature::NonTransferable(signer, signature);
        Self {
            reply: envelope,
            signature,
        }
    }

    pub fn new_trans(
        envelope: EventMessage<ReplyEvent>,
        signer_seal: EventSeal,
        signatures: Vec<AttachedSignaturePrefix>,
    ) -> Self {
        let signature = Signature::Transferable(signer_seal, signatures);
        Self {
            reply: envelope,
            signature,
        }
    }
}
