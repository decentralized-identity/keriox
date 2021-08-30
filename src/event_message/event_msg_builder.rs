use crate::{derivation::{basic::Basic, self_addressing::SelfAddressing}, error::Error, event::sections::key_config::nxt_commitment, event::{
        event_data::{
            delegated::{DelegatedInceptionEvent, DelegatedRotationEvent},
            interaction::InteractionEvent,
            rotation::RotationEvent,
        },
        sections::{threshold::SignatureThreshold, seal::LocationSeal, WitnessConfig},
        SerializationFormats,
    }, event::{
        event_data::{inception::InceptionEvent, EventData},
        sections::seal::Seal,
        sections::InceptionWitnessConfig,
        sections::KeyConfig,
        Event, EventMessage,
    }, prefix::{BasicPrefix, IdentifierPrefix, SelfAddressingPrefix, basic::PublicKey}};
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use std::str::FromStr;

pub struct EventMsgBuilder {
    event_type: EventType,
    prefix: IdentifierPrefix,
    sn: u64,
    key_threshold: SignatureThreshold,
    keys: Vec<BasicPrefix>,
    next_keys: Vec<BasicPrefix>,
    prev_event: SelfAddressingPrefix,
    data: Vec<Seal>,
    delegating_seal: LocationSeal,
    format: SerializationFormats,
    derivation: SelfAddressing,
}

#[derive(Clone, Debug)]
pub enum EventType {
    Inception,
    Rotation,
    Interaction,
    DelegatedInception,
    DelegatedRotation,
}

impl EventType {
    pub fn is_establishment_event(&self) -> bool {
        match self {
            EventType::Inception
            | EventType::Rotation
            | EventType::DelegatedInception
            | EventType::DelegatedRotation => true,
            _ => false,
        }
    }
}

impl EventMsgBuilder {
    pub fn new(event_type: EventType) -> Result<Self, Error> {
        let mut rng = OsRng {};
        let kp = Keypair::generate(&mut rng);
        let nkp = Keypair::generate(&mut rng);
        let pk = PublicKey::new(kp.public.to_bytes().to_vec());
        let npk = PublicKey::new(nkp.public.to_bytes().to_vec());
        let basic_pref = Basic::Ed25519.derive(pk);
        let dummy_loc_seal = LocationSeal {
            prefix: IdentifierPrefix::from_str("EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM")?,
            sn: 2,
            ilk: "ixn".into(),
            prior_digest: SelfAddressingPrefix::from_str(
                "E8JZAoTNZH3ULZ-i0dvaU6JR2nmwyYAfSVPzhzS6b5CM",
            )?,
        };
        Ok(EventMsgBuilder {
            event_type,
            prefix: IdentifierPrefix::default(),
            keys: vec![basic_pref],
            next_keys: vec![Basic::Ed25519.derive(npk)],
            key_threshold: SignatureThreshold::Simple(1),
            sn: 1,
            prev_event: SelfAddressing::Blake3_256.derive(&[0u8; 32]),
            data: vec![],
            delegating_seal: dummy_loc_seal,
            format: SerializationFormats::JSON,
            derivation: SelfAddressing::Blake3_256,
        })
    }

    pub fn with_prefix(self, prefix: IdentifierPrefix) -> Self {
        EventMsgBuilder { prefix, ..self }
    }

    pub fn with_keys(self, keys: Vec<BasicPrefix>) -> Self {
        EventMsgBuilder { keys, ..self }
    }

    pub fn with_next_keys(self, next_keys: Vec<BasicPrefix>) -> Self {
        EventMsgBuilder { next_keys, ..self }
    }

    pub fn with_sn(self, sn: u64) -> Self {
        EventMsgBuilder { sn, ..self }
    }
    pub fn with_previous_event(self, prev_event: SelfAddressingPrefix) -> Self {
        EventMsgBuilder { prev_event, ..self }
    }

    pub fn with_seal(mut self, seals: Vec<Seal>) -> Self {
        self.data.extend(seals);
        EventMsgBuilder { ..self }
    }

    pub fn with_delegating_seal(self, seal: LocationSeal) -> Self {
        EventMsgBuilder {
            delegating_seal: seal,
            ..self
        }
    }

    pub fn with_threshold(self, threshold: SignatureThreshold) -> Self {
        EventMsgBuilder {
            key_threshold: threshold,
            ..self
        }
    }

    pub fn build(self) -> Result<EventMessage, Error> {
        let next_key_hash = nxt_commitment(
            &self.key_threshold,
            &self.next_keys,
            &SelfAddressing::Blake3_256,
        );
        let key_config = KeyConfig::new(self.keys, Some(next_key_hash), Some(self.key_threshold));
        let prefix =
            if self.prefix == IdentifierPrefix::default() && key_config.public_keys.len() == 1 {
                IdentifierPrefix::Basic(key_config.clone().public_keys[0].clone())
            } else {
                self.prefix
            };

        Ok(match self.event_type {
            EventType::Inception => {
                let icp_event = InceptionEvent {
                    key_config: key_config,
                    witness_config: InceptionWitnessConfig::default(),
                    inception_configuration: vec![],
                    data: vec![],
                };

                match prefix {
                    IdentifierPrefix::Basic(_) => Event {
                        prefix: prefix,
                        sn: 0,
                        event_data: EventData::Icp(icp_event),
                    }
                    .to_message(self.format)?,
                    IdentifierPrefix::SelfAddressing(_) => {
                        icp_event.incept_self_addressing(self.derivation, self.format)?
                    }
                    _ => todo!(),
                }
            }

            EventType::Rotation => Event {
                prefix: prefix,
                sn: self.sn,
                event_data: EventData::Rot(RotationEvent {
                    previous_event_hash: self.prev_event,
                    key_config: key_config,
                    witness_config: WitnessConfig::default(),
                    data: self.data,
                }),
            }
            .to_message(self.format)?,
            EventType::Interaction => Event {
                prefix: prefix,
                sn: self.sn,
                event_data: EventData::Ixn(InteractionEvent {
                    previous_event_hash: self.prev_event,
                    data: self.data,
                }),
            }
            .to_message(self.format)?,
            EventType::DelegatedInception => {
                let icp_data = InceptionEvent {
                    key_config: key_config,
                    witness_config: InceptionWitnessConfig::default(),
                    inception_configuration: vec![],
                    data: vec![],
                };
                DelegatedInceptionEvent {
                    inception_data: icp_data,
                    seal: self.delegating_seal,
                }
                .incept_self_addressing(self.derivation, self.format)?
            }
            EventType::DelegatedRotation => {
                let rotation_data = RotationEvent {
                    previous_event_hash: self.prev_event,
                    key_config: key_config,
                    witness_config: WitnessConfig::default(),
                    data: self.data,
                };
                Event {
                    prefix: prefix,
                    sn: self.sn,
                    event_data: EventData::Drt(DelegatedRotationEvent {
                        rotation_data,
                        seal: self.delegating_seal,
                    }),
                }
                .to_message(self.format)?
            }
        })
    }
}
