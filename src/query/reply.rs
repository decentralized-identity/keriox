use chrono::{DateTime, FixedOffset, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    derivation::self_addressing::SelfAddressing,
    error::Error,
    event::{sections::seal::EventSeal, EventMessage, SerializationFormats},
    prefix::{
        AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, SelfAddressingPrefix,
        SelfSigningPrefix,
    }, state::IdentifierState,
};

use super::{key_state_notice::KeyStateNotice, Envelope, QueryError, Route, Signature};

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ReplyData {
    #[serde(rename = "d")]
    pub digest: Option<SelfAddressingPrefix>,
    #[serde(rename = "a")]
    pub data: EventMessage<KeyStateNotice>,
}

pub type Reply = EventMessage<Envelope<ReplyData>>;

impl Reply {
    pub fn new_reply(
        ksn: EventMessage<KeyStateNotice>,
        route: Route,
        self_addressing: SelfAddressing,
        serialization: SerializationFormats,
    ) -> EventMessage<Envelope<ReplyData>> {
        // To create reply message we need to use dummy string in digest field,
        // compute digest and update `d` field.
        let rpy_data = ReplyData {
            digest: None,
            data: ksn.clone(),
        };
        let env = Envelope {
            timestamp: Utc::now().into(),
            route: route.clone(),
            data: rpy_data,
        };
        let ev_msg = EventMessage::new(env.clone(), serialization).unwrap();
        let dig = self_addressing.derive(&ev_msg.serialize().unwrap());
        let version = ev_msg.serialization_info;
        let rpy_data = ReplyData {
            digest: Some(dig),
            data: ksn,
        };
        let env = Envelope {
            data: rpy_data,
            ..env
        };
        EventMessage {
            serialization_info: version,
            event: env,
        }
    }

    pub fn get_timestamp(&self) -> DateTime<FixedOffset> {
        self.event.timestamp
    }

    pub fn get_prefix(&self) -> IdentifierPrefix {
        self.event.data.data.event.state.prefix.clone()
    }


    pub fn get_state(&self) -> IdentifierState {
        self.event.data.data.event.state.clone()
    }

    fn with_dummy_digest(&self) -> Vec<u8> {
        let mut def_dig = self.clone();
        def_dig.event.data.digest = None;
        def_dig.serialize().unwrap()
    }

    fn get_digest(&self) -> Option<SelfAddressingPrefix> {
        self.event.data.digest.clone()
    }

    pub fn check_digest(&self) -> Result<(), Error> {
        let digest = self.get_digest().unwrap();
        digest
            .verify_binding(&self.with_dummy_digest())
            .then(|| ())
            .ok_or(QueryError::IncorrectDigest.into())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SignedReply {
    pub reply: Reply,
    pub signature: Signature,
}

impl SignedReply {
    pub fn new_nontrans(
        envelope: EventMessage<Envelope<ReplyData>>,
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
        envelope: EventMessage<Envelope<ReplyData>>,
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
    // From keripy
    let rpy = r#"{"v":"KERI10JSON000294_","t":"rpy","d":"EPeNPAtRcVjY7lLxl_DZ3qFPb0R0n_6wmGAMgO-u8_YU","dt":"2021-01-01T00:00:00.000000+00:00","r":"/ksn/BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY","a":{"v":"KERI10JSON0001d9_","i":"E4BsxCYUtUx3d6UkDVIQ9Ke3CLQfqWBfICSmjIzkS1u4","s":"0","p":"","d":"EYk4PigtRsCd5W2so98c8r8aeRHoixJK7ntv9mTrZPmM","f":"0","dt":"2021-01-01T00:00:00.000000+00:00","et":"icp","kt":"1","k":["DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"],"n":"E7FuL3Z_KBgt_QAwuZi1lUFNC69wvyHSxnMFUsKjZHss","bt":"1","b":["BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY"],"c":[],"ee":{"s":"0","d":"EYk4PigtRsCd5W2so98c8r8aeRHoixJK7ntv9mTrZPmM","br":[],"ba":[]},"di":""}}"#;

    let qr: Result<Reply, _> = serde_json::from_str(rpy);
    assert!(qr.is_ok());
    let qr = qr.unwrap();

    assert_eq!(serde_json::to_string(&qr).unwrap(), rpy);
}
