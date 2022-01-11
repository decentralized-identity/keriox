use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};

use crate::{
    derivation::self_addressing::SelfAddressing,
    error::Error,
    event::{sections::seal::EventSeal, EventMessage, SerializationFormats},
    prefix::{
        AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, 
        SelfSigningPrefix,
    }, state::IdentifierState, event_message::{signature::Signature, dummy_event::DummyEventMessage, Typeable, SaidEvent, Digestible},
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
        let rpy_data = ReplyData {
            data: ksn.clone(),
        };
        let env = Envelope::new(
            route.clone(),
            rpy_data,
        );
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
            &self.event.get_digest().unwrap().derivation
        )?.serialize()?;
        self.event.get_digest()
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

#[test]
fn test_reply_deserialize() {
    // From keripy (keripy/tests/core/test_keystate.py::100)
    let rpy = r#"{"v":"KERI10JSON000294_","t":"rpy","d":"EzXrBzyJK1ELAGw9VZIbeT-e5JTYQvQAvNIlSEfVgJSk","dt":"2021-01-01T00:00:00.000000+00:00","r":"/ksn/BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY","a":{"v":"KERI10JSON0001d9_","i":"ECJTKtR-GlybCmn1PCiVwIuGBjaOUXI09XWDdXkrJNj0","s":"0","p":"","d":"ECJTKtR-GlybCmn1PCiVwIuGBjaOUXI09XWDdXkrJNj0","f":"0","dt":"2021-01-01T00:00:00.000000+00:00","et":"icp","kt":"1","k":["DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"],"n":"E7FuL3Z_KBgt_QAwuZi1lUFNC69wvyHSxnMFUsKjZHss","bt":"1","b":["BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY"],"c":[],"ee":{"s":"0","d":"ECJTKtR-GlybCmn1PCiVwIuGBjaOUXI09XWDdXkrJNj0","br":[],"ba":[]},"di":""}}"#;

    let qr: Result<EventMessage<ReplyEvent>, _> = serde_json::from_str(rpy);
    assert!(qr.is_ok());
    let qr = qr.unwrap();

    assert_eq!(serde_json::to_string(&qr).unwrap(), rpy);
}
