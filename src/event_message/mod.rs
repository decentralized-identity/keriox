pub mod dummy_event;
pub mod event_msg_builder;
pub mod key_event_message;
pub mod serialization_info;
pub mod serializer;
pub mod signature;
pub mod signed_event_message;

use std::cmp::Ordering;

use crate::{
    derivation::self_addressing::SelfAddressing, error::Error, prefix::SelfAddressingPrefix,
};
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize, Serializer};
use serialization_info::*;

use self::{dummy_event::DummyEventMessage, key_event_message::KeyEvent};

pub trait Typeable {
    fn get_type(&self) -> EventTypeTag;
}
pub trait Digestible {
    fn get_digest(&self) -> SelfAddressingPrefix;
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum EventTypeTag {
    Icp,
    Rot,
    Ixn,
    Dip,
    Drt,
    Rct,
    #[cfg(feature = "query")]
    Rpy,
    #[cfg(feature = "query")]
    Qry,
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SaidEvent<D> {
    #[serde(rename = "d", skip_serializing)]
    digest: SelfAddressingPrefix,

    #[serde(flatten)]
    pub content: D,
}

impl<D: Serialize + Clone + Typeable> SaidEvent<D> {
    pub fn new(digest: SelfAddressingPrefix, content: D) -> Self {
        Self {
            digest: digest,
            content,
        }
    }
    pub(crate) fn to_message(
        event: D,
        format: SerializationFormats,
        derivation: &SelfAddressing,
    ) -> Result<EventMessage<SaidEvent<D>>, Error> {
        let dummy_event = DummyEventMessage::dummy_event(event.clone(), format, &derivation)?;
        let digest = derivation.derive(&dummy_event.serialize()?);

        Ok(EventMessage {
            serialization_info: dummy_event.serialization_info,
            event: Self {
                digest,
                content: event,
            },
        })
    }
}

impl<D> Digestible for SaidEvent<D> {
    fn get_digest(&self) -> SelfAddressingPrefix {
        self.digest.clone()
    }
}

impl<D: Typeable> Typeable for SaidEvent<D> {
    fn get_type(&self) -> EventTypeTag {
        self.content.get_type()
    }
}

#[derive(Default, Deserialize, Debug, Clone, PartialEq)]
pub struct EventMessage<D> {
    /// Serialization Information
    ///
    /// Encodes the version, size and serialization format of the event
    #[serde(rename = "v")]
    pub serialization_info: SerializationInfo,

    #[serde(flatten)]
    pub event: D,
}

impl<D: Digestible> EventMessage<D> {
    pub fn get_digest(&self) -> SelfAddressingPrefix {
        self.event.get_digest()
    }
}

impl<D: Digestible + Typeable + Serialize + Clone> Serialize for EventMessage<D> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Helper struct for adding `t` field to EventMessage serialization
        #[derive(Serialize)]
        struct TypedEventMessage<D> {
            v: SerializationInfo,
            #[serde(rename = "t")]
            event_type: EventTypeTag,

            #[serde(rename = "d")]
            digest: SelfAddressingPrefix,

            #[serde(flatten)]
            event: D,
        }
        impl<D: Digestible + Typeable + Clone> From<&EventMessage<D>> for TypedEventMessage<D> {
            fn from(em: &EventMessage<D>) -> Self {
                TypedEventMessage {
                    v: em.serialization_info,
                    event_type: em.event.get_type(),
                    digest: em.event.get_digest(),
                    event: em.event.clone(),
                }
            }
        }

        let tem: TypedEventMessage<_> = self.into();
        tem.serialize(serializer)
    }
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct TimestampedEventMessage {
    pub timestamp: DateTime<Local>,
    pub event_message: EventMessage<KeyEvent>,
}

impl TimestampedEventMessage {
    pub fn new(event: EventMessage<KeyEvent>) -> Self {
        Self {
            timestamp: Local::now(),
            event_message: event,
        }
    }
}

impl PartialOrd for TimestampedEventMessage {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(
            match self.event_message.event.get_sn() == other.event_message.event.get_sn() {
                true => Ordering::Equal,
                false => {
                    match self.event_message.event.get_sn() > other.event_message.event.get_sn() {
                        true => Ordering::Greater,
                        false => Ordering::Less,
                    }
                }
            },
        )
    }
}

impl Ord for TimestampedEventMessage {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.event_message.event.get_sn() == other.event_message.event.get_sn() {
            true => Ordering::Equal,
            false => match self.event_message.event.get_sn() > other.event_message.event.get_sn() {
                true => Ordering::Greater,
                false => Ordering::Less,
            },
        }
    }
}

impl Eq for TimestampedEventMessage {}

impl From<TimestampedEventMessage> for EventMessage<KeyEvent> {
    fn from(event: TimestampedEventMessage) -> EventMessage<KeyEvent> {
        event.event_message
    }
}

/// WARNING: timestamp will change on conversion to current time
impl From<EventMessage<KeyEvent>> for TimestampedEventMessage {
    fn from(event: EventMessage<KeyEvent>) -> TimestampedEventMessage {
        TimestampedEventMessage::new(event)
    }
}

impl<T: Clone + Serialize + Digestible + Typeable> EventMessage<T> {
    pub fn serialization(&self) -> SerializationFormats {
        self.serialization_info.kind
    }

    /// Serialize
    ///
    /// returns the serialized event message
    /// NOTE: this method, for deserialized events, will be UNABLE to preserve ordering
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        self.serialization().encode(self)
    }
}

#[cfg(test)]
mod tests {
    mod test_utils;

    use self::test_utils::test_mock_event_sequence;
    use super::*;
    use crate::{
        derivation::{basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning},
        event::{
            event_data::{inception::InceptionEvent, EventData},
            sections::KeyConfig,
            sections::{threshold::SignatureThreshold, InceptionWitnessConfig},
            Event,
        },
        keys::{PrivateKey, PublicKey},
        prefix::{AttachedSignaturePrefix, IdentifierPrefix, Prefix},
        state::IdentifierState,
    };
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;

    #[test]
    fn basic_create() -> Result<(), Error> {
        // hi Ed!
        let kp0 = Keypair::generate(&mut OsRng);
        let kp1 = Keypair::generate(&mut OsRng);

        // get two ed25519 keypairs
        let pub_key0 = PublicKey::new(kp0.public.to_bytes().to_vec());
        let priv_key0 = PrivateKey::new(kp0.secret.to_bytes().to_vec());
        let (pub_key1, _priv_key1) = (
            PublicKey::new(kp1.public.to_bytes().to_vec()),
            PrivateKey::new(kp1.secret.to_bytes().to_vec()),
        );

        // initial signing key prefix
        let pref0 = Basic::Ed25519.derive(pub_key0);

        // initial control key hash prefix
        let pref1 = Basic::Ed25519.derive(pub_key1);
        let nxt = SelfAddressing::Blake3_256.derive(pref1.to_str().as_bytes());

        // create a simple inception event
        let icp = Event::new(
            IdentifierPrefix::Basic(pref0.clone()),
            0,
            EventData::Icp(InceptionEvent {
                key_config: KeyConfig::new(
                    vec![pref0.clone()],
                    Some(nxt.clone()),
                    Some(SignatureThreshold::Simple(1)),
                ),
                witness_config: InceptionWitnessConfig::default(),
                inception_configuration: vec![],
                data: vec![],
            }),
        );

        let icp_m = icp.to_message(SerializationFormats::JSON, &SelfAddressing::Blake3_256)?;

        // serialised message
        let ser: Vec<_> = icp_m.serialize()?;

        // sign
        let sig = priv_key0.sign_ed(&ser)?;
        let attached_sig = AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, sig, 0);

        assert!(pref0.verify(&ser, &attached_sig.signature)?);

        let signed_event = icp_m.sign(vec![attached_sig], None);

        let s_ = IdentifierState::default();

        let s0 = s_.apply(&signed_event)?;

        assert!(s0.current.verify(&ser, &signed_event.signatures)?);

        assert_eq!(s0.prefix, IdentifierPrefix::Basic(pref0.clone()));
        assert_eq!(s0.sn, 0);
        assert!(icp_m.check_digest(&s0.last_event_digest)?);
        assert_eq!(s0.current.public_keys.len(), 1);
        assert_eq!(s0.current.public_keys[0], pref0);
        assert_eq!(s0.current.threshold, SignatureThreshold::Simple(1));
        assert_eq!(s0.current.threshold_key_digest, Some(nxt));
        assert_eq!(s0.witnesses, vec![]);
        assert_eq!(s0.tally, 0);

        Ok(())
    }

    #[test]
    fn self_addressing_create() -> Result<(), Error> {
        // hi Ed!
        let kp0 = Keypair::generate(&mut OsRng);
        let kp1 = Keypair::generate(&mut OsRng);
        let kp2 = Keypair::generate(&mut OsRng);

        // get two ed25519 keypairs
        let pub_key0 = PublicKey::new(kp0.public.to_bytes().to_vec());
        let priv_key0 = PrivateKey::new(kp0.secret.to_bytes().to_vec());
        let (pub_key1, sig_key_1) = (
            PublicKey::new(kp1.public.to_bytes().to_vec()),
            PrivateKey::new(kp1.secret.to_bytes().to_vec()),
        );

        // hi X!
        // let x = XChaCha20Poly1305::new((&priv_key0.into_bytes()[..]).into());

        // get two X25519 keypairs
        let (enc_key_0, _enc_priv_0) = (PublicKey::new(kp2.public.to_bytes().to_vec()), sig_key_1);
        let (enc_key_1, _enc_priv_1) = (
            PublicKey::new(kp2.public.to_bytes().to_vec()),
            PrivateKey::new(kp2.secret.to_bytes().to_vec()),
        );

        // initial key set
        let sig_pref_0 = Basic::Ed25519.derive(pub_key0);
        let enc_pref_0 = Basic::X25519.derive(enc_key_0);

        // next key set
        let sig_pref_1 = Basic::Ed25519.derive(pub_key1);
        let enc_pref_1 = Basic::X25519.derive(enc_key_1);

        // next key set pre-commitment
        let nexter_pref = SelfAddressing::Blake3_256.derive(
            [sig_pref_1.to_str(), enc_pref_1.to_str()]
                .join("")
                .as_bytes(),
        );

        let icp = InceptionEvent::new(
            KeyConfig::new(
                vec![sig_pref_0.clone(), enc_pref_0.clone()],
                Some(nexter_pref.clone()),
                Some(SignatureThreshold::default()),
            ),
            None,
            None,
        )
        .incept_self_addressing(SelfAddressing::Blake3_256, SerializationFormats::JSON)?;

        // serialised
        let serialized: Vec<_> = icp.serialize()?;

        // sign
        let sk = priv_key0;
        let sig = sk.sign_ed(&serialized)?;
        let attached_sig = AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, sig, 0);

        assert!(sig_pref_0.verify(&serialized, &attached_sig.signature)?);

        let signed_event = icp.sign(vec![attached_sig], None);

        let s_ = IdentifierState::default();

        let s0 = s_.apply(&signed_event)?;

        assert!(s0.current.verify(&serialized, &signed_event.signatures)?);

        assert_eq!(s0.prefix, icp.event.get_prefix());
        assert_eq!(s0.sn, 0);
        assert!(icp.check_digest(&s0.last_event_digest)?);
        assert_eq!(s0.current.public_keys.len(), 2);
        assert_eq!(s0.current.public_keys[0], sig_pref_0);
        assert_eq!(s0.current.public_keys[1], enc_pref_0);
        assert_eq!(s0.current.threshold, SignatureThreshold::default());
        assert_eq!(s0.current.threshold_key_digest, Some(nexter_pref));
        assert_eq!(s0.witnesses, vec![]);
        assert_eq!(s0.tally, 0);

        Ok(())
    }

    #[test]
    fn test_basic_establishment_sequence() -> Result<(), Error> {
        // Sequence should contain Inception Event.
        let no_inception_seq = vec![EventTypeTag::Rot, EventTypeTag::Rot];
        assert!(test_mock_event_sequence(no_inception_seq).is_err());

        // Sequence can't start with Rotation Event.
        let rotation_first_seq = vec![EventTypeTag::Rot, EventTypeTag::Icp];
        assert!(test_mock_event_sequence(rotation_first_seq).is_err());

        // Sequence should contain exacly one Inception Event.
        let wrong_seq = vec![
            EventTypeTag::Icp,
            EventTypeTag::Rot,
            EventTypeTag::Rot,
            EventTypeTag::Icp,
        ];
        assert!(test_mock_event_sequence(wrong_seq).is_err());

        let ok_seq = vec![EventTypeTag::Icp, EventTypeTag::Rot, EventTypeTag::Rot];
        assert!(test_mock_event_sequence(ok_seq).is_ok());

        // Wrong delegated events sequence.
        let wrong_delegated_sequence =
            vec![EventTypeTag::Dip, EventTypeTag::Drt, EventTypeTag::Rot];
        assert!(test_mock_event_sequence(wrong_delegated_sequence).is_err());

        // Delegated events sequence.
        let delegated_sequence = vec![EventTypeTag::Dip, EventTypeTag::Drt, EventTypeTag::Ixn];
        assert!(test_mock_event_sequence(delegated_sequence).is_ok());

        Ok(())
    }

    #[test]
    fn test_basic_sequence() -> Result<(), Error> {
        let ok_seq = vec![
            EventTypeTag::Icp,
            EventTypeTag::Ixn,
            EventTypeTag::Ixn,
            EventTypeTag::Ixn,
            EventTypeTag::Rot,
            EventTypeTag::Ixn,
        ];
        assert!(test_mock_event_sequence(ok_seq).is_ok());

        let delegated_sequence = vec![
            EventTypeTag::Dip,
            EventTypeTag::Drt,
            EventTypeTag::Ixn,
            EventTypeTag::Drt,
        ];
        assert!(test_mock_event_sequence(delegated_sequence).is_ok());

        Ok(())
    }
}
