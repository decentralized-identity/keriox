pub mod event_msg_builder;
pub mod parse;
pub mod serialization_info;
pub mod serializer;
pub mod payload_size;
pub mod signed_event_message;
pub mod attachement;

use std::cmp::Ordering;

use crate::{error::Error, event::{
        event_data::{DummyEvent, EventData},
        Event,
    }, prefix::{
       AttachedSignaturePrefix, IdentifierPrefix,
    }, state::{EventSemantics, IdentifierState}};
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use serialization_info::*;

use self::{payload_size::PayloadType, signed_event_message::SignedEventMessage};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct EventMessage {
    /// Serialization Information
    ///
    /// Encodes the version, size and serialization format of the event
    #[serde(rename = "v")]
    pub serialization_info: SerializationInfo,

    #[serde(flatten)]
    pub event: Event,
    // Additional Data for forwards compat
    //
    // TODO: Currently seems to be bugged, it captures and duplicates every element in the event
    // #[serde(flatten)]
    // pub extra: HashMap<String, Value>,
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct TimestampedEventMessage {
    pub timestamp: DateTime<Local>,
    pub event_message: EventMessage,
}

impl TimestampedEventMessage {
    pub fn new(event: EventMessage) -> Self {
        Self {
            timestamp: Local::now(),
            event_message: event,
        }
    }
}

impl PartialOrd for TimestampedEventMessage {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(match self.event_message.event.sn == other.event_message.event.sn {
            true => Ordering::Equal,
            false => match self.event_message.event.sn > other.event_message.event.sn {
                true => Ordering::Greater,
                false => Ordering::Less,
            },
        })
    }
}

impl Ord for TimestampedEventMessage {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.event_message.event.sn == other.event_message.event.sn {
            true => Ordering::Equal,
            false => match self.event_message.event.sn > other.event_message.event.sn {
                true => Ordering::Greater,
                false => Ordering::Less,
            },
        }
    }
}

impl Eq for TimestampedEventMessage {}

impl From<TimestampedEventMessage> for EventMessage {
    fn from(event: TimestampedEventMessage) -> EventMessage {
        event.event_message
    }
}

/// WARNING: timestamp will change on conversion to current time
impl From<EventMessage> for TimestampedEventMessage {
    fn from(event: EventMessage) -> TimestampedEventMessage {
        TimestampedEventMessage::new(event)
    }
}

impl EventMessage {
    pub fn new(event: Event, format: SerializationFormats) -> Result<Self, Error> {
        Ok(Self {
            serialization_info: SerializationInfo::new(format, Self::get_size(&event, format)?),
            event,
        })
    }

    fn get_size(event: &Event, format: SerializationFormats) -> Result<usize, Error> {
        Ok(Self {
            serialization_info: SerializationInfo::new(format, 0),
            event: event.clone(),
        }
        .serialize()?
        .len())
    }

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

    pub fn sign(&self, payload_type: PayloadType, sigs: Vec<AttachedSignaturePrefix>) -> SignedEventMessage {
        SignedEventMessage::new(self, payload_type, sigs)
    }
}

impl EventSemantics for EventMessage {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        // Update state.last with serialized current event message.
        match self.event.event_data {
            EventData::Icp(_) | EventData::Dip(_) => {
                if verify_identifier_binding(self)? {
                    self.event.apply_to(IdentifierState {
                        last: self.serialize()?,
                        ..state
                    })
                } else {
                    Err(Error::SemanticError(
                        "Invalid Identifier Prefix Binding".into(),
                    ))
                }
            }
            EventData::Rot(ref rot) => {
                if let Some(_) = state.delegator {
                    Err(Error::SemanticError(
                        "Applying non-delegated rotation to delegated state.".into(),
                    ))
                } else {
                    // Event may be out of order or duplicated, so before checking
                    // previous event hash binding and update state last, apply it
                    // to the state. It will return EventOutOfOrderError or
                    // EventDuplicateError in that cases.
                    self.event.apply_to(state.clone()).and_then(|next_state| {
                        if rot.previous_event_hash.verify_binding(&state.last) {
                            Ok(IdentifierState {
                                last: self.serialize()?,
                                ..next_state
                            })
                        } else {
                            Err(Error::SemanticError(
                                "Last event does not match previous event".into(),
                            ))
                        }
                    })
                }
            }
            EventData::Drt(ref drt) => self.event.apply_to(state.clone()).and_then(|next_state| {
                if let None = state.delegator {
                    Err(Error::SemanticError(
                        "Applying delegated rotation to non-delegated state.".into(),
                    ))
                } else if drt
                    .rotation_data
                    .previous_event_hash
                    .verify_binding(&state.last)
                {
                    Ok(IdentifierState {
                        last: self.serialize()?,
                        ..next_state
                    })
                } else {
                    Err(Error::SemanticError(
                        "Last event does not match previous event".into(),
                    ))
                }
            }),
            EventData::Ixn(ref inter) => {
                self.event.apply_to(state.clone()).and_then(|next_state| {
                    if inter.previous_event_hash.verify_binding(&state.last) {
                        Ok(IdentifierState {
                            last: self.serialize()?,
                            ..next_state
                        })
                    } else {
                        Err(Error::SemanticError(
                            "Last event does not match previous event".to_string(),
                        ))
                    }
                })
            }

            _ => self.event.apply_to(state),
        }
    }
}

pub fn verify_identifier_binding(icp_event: &EventMessage) -> Result<bool, Error> {
    let event_data = &icp_event.event.event_data;
    match event_data {
        EventData::Icp(icp) => match &icp_event.event.prefix {
            IdentifierPrefix::Basic(bp) => Ok(icp.key_config.public_keys.len() == 1
                && bp == icp.key_config.public_keys.first().unwrap()),
            // TODO update with new inception process
            IdentifierPrefix::SelfAddressing(sap) => {
                Ok(sap.verify_binding(&DummyEvent::derive_inception_data(
                    icp.clone(),
                    &sap.derivation,
                    icp_event.serialization(),
                )?))
            }
            IdentifierPrefix::SelfSigning(_ssp) => todo!(),
        },
        EventData::Dip(dip) => match &icp_event.event.prefix {
            IdentifierPrefix::SelfAddressing(sap) => Ok(sap.verify_binding(
                &DummyEvent::derive_delegated_inception_data(
                    dip.clone(),
                    &sap.derivation,
                    icp_event.serialization(),
                )?,
            )),
            _ => todo!(),
        },
        _ => Err(Error::SemanticError("Not an ICP or DIP event".into())),
    }
}

#[cfg(test)]
mod tests {
    mod test_utils;

    use self::{event_msg_builder::EventType, test_utils::test_mock_event_sequence};
    use super::*;
    use crate::{derivation::{basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning}, event::{
            event_data::{inception::InceptionEvent, EventData},
            sections::KeyConfig,
            sections::{threshold::SignatureThreshold, InceptionWitnessConfig},
        }, keys::{PrivateKey, PublicKey}, prefix::{Prefix, AttachedSignaturePrefix, IdentifierPrefix }};
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
        let icp = Event {
            prefix: IdentifierPrefix::Basic(pref0.clone()),
            sn: 0,
            event_data: EventData::Icp(InceptionEvent {
                key_config: KeyConfig::new(
                    vec![pref0.clone()],
                    Some(nxt.clone()),
                    Some(SignatureThreshold::Simple(1)),
                ),
                witness_config: InceptionWitnessConfig::default(),
                inception_configuration: vec![],
                data: vec![],
            }),
        };

        let icp_m = icp.to_message(SerializationFormats::JSON)?;

        // serialised message
        let ser = icp_m.serialize()?;

        // sign
        let sig = priv_key0.sign_ed(&ser)?;
        let attached_sig = AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, sig, 0);

        assert!(pref0.verify(&ser, &attached_sig.signature)?);

        let signed_event = icp_m.sign(PayloadType::MA, vec![attached_sig]);

        let s_ = IdentifierState::default();

        let s0 = s_.apply(&signed_event)?;

        assert!(s0.current.verify(&ser, &signed_event.signatures)?);

        assert_eq!(s0.prefix, IdentifierPrefix::Basic(pref0.clone()));
        assert_eq!(s0.sn, 0);
        assert_eq!(s0.last, ser);
        assert_eq!(s0.current.public_keys.len(), 1);
        assert_eq!(s0.current.public_keys[0], pref0);
        assert_eq!(s0.current.threshold, SignatureThreshold::Simple(1));
        assert_eq!(s0.current.threshold_key_digest, Some(nxt));
        assert_eq!(s0.witnesses, vec![]);
        assert_eq!(s0.tally, 0);
        assert_eq!(s0.delegates, vec![]);

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
        let serialized = icp.serialize()?;

        // sign
        let sk = priv_key0;
        let sig = sk.sign_ed(&serialized)?;
        let attached_sig = AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, sig, 0);

        assert!(sig_pref_0.verify(&serialized, &attached_sig.signature)?);

        let signed_event = icp.sign(PayloadType::MA, vec![attached_sig]);

        let s_ = IdentifierState::default();

        let s0 = s_.apply(&signed_event)?;

        assert!(s0.current.verify(&serialized, &signed_event.signatures)?);

        assert_eq!(s0.prefix, icp.event.prefix);
        assert_eq!(s0.sn, 0);
        assert_eq!(s0.last, serialized);
        assert_eq!(s0.current.public_keys.len(), 2);
        assert_eq!(s0.current.public_keys[0], sig_pref_0);
        assert_eq!(s0.current.public_keys[1], enc_pref_0);
        assert_eq!(s0.current.threshold, SignatureThreshold::default());
        assert_eq!(s0.current.threshold_key_digest, Some(nexter_pref));
        assert_eq!(s0.witnesses, vec![]);
        assert_eq!(s0.tally, 0);
        assert_eq!(s0.delegates, vec![]);

        Ok(())
    }

    #[test]
    fn test_basic_establishment_sequence() -> Result<(), Error> {
        // Sequence should contain Inception Event.
        let no_inception_seq = vec![EventType::Rotation, EventType::Rotation];
        assert!(test_mock_event_sequence(no_inception_seq).is_err());

        // Sequence can't start with Rotation Event.
        let rotation_first_seq = vec![EventType::Rotation, EventType::Inception];
        assert!(test_mock_event_sequence(rotation_first_seq).is_err());

        // Sequence should contain exacly one Inception Event.
        let wrong_seq = vec![
            EventType::Inception,
            EventType::Rotation,
            EventType::Rotation,
            EventType::Inception,
        ];
        assert!(test_mock_event_sequence(wrong_seq).is_err());

        let ok_seq = vec![
            EventType::Inception,
            EventType::Rotation,
            EventType::Rotation,
        ];
        assert!(test_mock_event_sequence(ok_seq).is_ok());

        // Wrong delegated events sequence.
        let wrong_delegated_sequence = vec![
            EventType::DelegatedInception,
            EventType::DelegatedRotation,
            EventType::Rotation,
        ];
        assert!(test_mock_event_sequence(wrong_delegated_sequence).is_err());

        // Delegated events sequence.
        let delegated_sequence = vec![
            EventType::DelegatedInception,
            EventType::DelegatedRotation,
            EventType::Interaction,
        ];
        assert!(test_mock_event_sequence(delegated_sequence).is_ok());

        Ok(())
    }

    #[test]
    fn test_basic_sequence() -> Result<(), Error> {
        let ok_seq = vec![
            EventType::Inception,
            EventType::Interaction,
            EventType::Interaction,
            EventType::Interaction,
            EventType::Rotation,
            EventType::Interaction,
        ];
        assert!(test_mock_event_sequence(ok_seq).is_ok());

        let delegated_sequence = vec![
            EventType::DelegatedInception,
            EventType::DelegatedRotation,
            EventType::Interaction,
            EventType::DelegatedRotation,
        ];
        assert!(test_mock_event_sequence(delegated_sequence).is_ok());

        Ok(())
    }
}
