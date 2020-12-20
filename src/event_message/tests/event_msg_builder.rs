use std::str::FromStr;

use crate::{
    derivation::self_signing::SelfSigning,
    derivation::{basic::Basic, self_addressing::SelfAddressing},
    error::Error,
    event::sections::nxt_commitment,
    event::{
        event_data::{
            delegated::{DelegatedInceptionEvent, DelegatedRotationEvent},
            interaction::InteractionEvent,
            rotation::RotationEvent,
        },
        sections::{seal::LocationSeal, WitnessConfig},
        SerializationFormats,
    },
    event::{
        event_data::{inception::InceptionEvent, EventData},
        sections::seal::Seal,
        sections::InceptionWitnessConfig,
        sections::KeyConfig,
        Event, EventMessage,
    },
    event_message::{parse::message, SignedEventMessage},
    prefix::AttachedSignaturePrefix,
    prefix::Prefix,
    prefix::{BasicPrefix, IdentifierPrefix, SelfAddressingPrefix},
    signer::CryptoBox,
};

pub struct EventMsgBuilder {
    event_type: EventType,
    prefix: IdentifierPrefix,
    sn: u64,
    key_threshold: u64,
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
        let key_manager = CryptoBox::new().unwrap();
        let basic_pref = Basic::Ed25519.derive(key_manager.public_key());
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
            prefix: IdentifierPrefix::Basic(basic_pref.clone()),
            keys: vec![basic_pref],
            next_keys: vec![Basic::Ed25519.derive(key_manager.next_pub_key.clone())],
            key_threshold: 1,
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

    pub fn build(self) -> Result<EventMessage, Error> {
        let next_key_hash = nxt_commitment(1, &self.next_keys, SelfAddressing::Blake3_256);
        let key_config = KeyConfig::new(self.keys, next_key_hash, Some(self.key_threshold));

        Ok(match self.event_type {
            EventType::Inception => {
                let icp_event = InceptionEvent {
                    key_config: key_config,
                    witness_config: InceptionWitnessConfig::default(),
                    inception_configuration: vec![],
                };
                match self.prefix {
                    IdentifierPrefix::Basic(_) => Event {
                        prefix: self.prefix,
                        sn: self.sn,
                        event_data: EventData::Icp(icp_event),
                    }
                    .to_message(SerializationFormats::JSON)?,
                    IdentifierPrefix::SelfAddressing(_) => {
                        icp_event.incept_self_addressing(self.derivation, self.format)?
                    }
                    _ => todo!(),
                }
            }

            EventType::Rotation => Event {
                prefix: self.prefix,
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
                prefix: self.prefix,
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
                    prefix: self.prefix,
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
pub struct SignedMsgBuilder {
    msg: EventMessage,
    signers: Vec<CryptoBox>,
}

impl SignedMsgBuilder {
    pub fn new(event_type: EventType, n: u64) -> Result<Self, Error> {
        // Generate n signers.
        let managers = (0..n)
            .map(|_| CryptoBox::new().unwrap())
            .collect::<Vec<_>>();
        let cur_keys = managers
            .iter()
            .map(|m| Basic::Ed25519.derive(m.public_key()))
            .collect();
        let nxt_keys = managers
            .iter()
            .map(|m| Basic::Ed25519.derive(m.next_pub_key.clone()))
            .collect();
        Ok(Self {
            msg: EventMsgBuilder::new(event_type)?
                .with_keys(cur_keys)
                .with_next_keys(nxt_keys)
                .build()?,
            signers: managers,
        })
    }

    pub fn build(&self) -> Result<SignedEventMessage, Error> {
        let ser_msg = self.msg.serialize()?;
        let signatures: Vec<AttachedSignaturePrefix> = self
            .signers
            .iter()
            .map(|s| s.sign(&ser_msg))
            .map(|sig| AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, sig.unwrap(), 0))
            .collect();

        Ok(self.msg.sign(signatures))
    }
}

#[test]
fn test_generation() -> Result<(), Error> {
    let ev = EventMsgBuilder::new(EventType::Inception)?.build()?;
    let icp = ev.serialize()?;
    let d = message(&icp);
    assert!(d.is_ok());
    assert_eq!(d.unwrap().1.event.serialize()?, icp);
    println!("{}\n", String::from_utf8(icp).unwrap());

    // Inception with three keys and signatures.
    let signed_icp = SignedMsgBuilder::new(EventType::Inception, 3)?.build()?;
    println!("{}\n", String::from_utf8(signed_icp.serialize()?).unwrap());
    println!(
        "event: {}\n",
        String::from_utf8(signed_icp.event_message.serialize()?).unwrap()
    );
    println!("sigs: {}\n", signed_icp.signatures[0].to_str());
    println!("sigs: {}\n", signed_icp.signatures[1].to_str());
    println!("sigs: {}\n", signed_icp.signatures[2].to_str());

    let ev = EventMsgBuilder::new(EventType::Rotation)?.build()?;
    let rot = ev.serialize()?;
    let d = message(&rot);
    assert!(d.is_ok());
    assert_eq!(d.unwrap().1.event.serialize()?, rot);
    println!("{}\n", String::from_utf8(rot).unwrap());

    let ev = EventMsgBuilder::new(EventType::Interaction)?.build()?;
    let ixn = ev.serialize()?;
    let d = message(&ixn);
    assert!(d.is_ok());
    assert_eq!(d.unwrap().1.event.serialize()?, ixn);
    println!("{}\n", String::from_utf8(ixn).unwrap());

    let ev = EventMsgBuilder::new(EventType::DelegatedInception)?.build()?;
    let dip = ev.serialize()?;
    let d = message(&dip);
    assert!(d.is_ok());
    assert_eq!(d.unwrap().1.event.serialize()?, dip);
    println!("{}\n", String::from_utf8(dip).unwrap());

    let ev = EventMsgBuilder::new(EventType::DelegatedRotation)?.build()?;
    let drt = ev.serialize()?;
    let d = message(&drt);
    assert!(d.is_ok());
    assert_eq!(d.unwrap().1.event.serialize()?, drt);
    println!("{}\n", String::from_utf8(drt).unwrap());

    Ok(())
}
