use keri::{
    derivation::{basic::Basic, self_addressing::SelfAddressing},
    error::Error,
    event::{
        event_data::{
            inception::InceptionEvent, interaction::InteractionEvent, receipt::ReceiptTransferable,
            rotation::RotationEvent, EventData,
        },
        sections::seal::DigestSeal,
        sections::{seal::EventSeal, seal::Seal, InceptionWitnessConfig, KeyConfig, WitnessConfig},
        Event,
    },
    event_message::{
        parse::signed_event_stream, serialization_info::SerializationFormats, EventMessage,
        SignedEventMessage,
    },
    prefix::{IdentifierPrefix, Prefix},
    signer::Signer,
    state::IdentifierState,
    util::dfs_serializer,
};
use serde_json::to_string_pretty;
use std::{collections::HashMap, str::from_utf8};

pub struct LogState {
    pub log: Vec<SignedEventMessage>,
    pub state: IdentifierState,
    pub receipts: HashMap<u64, Vec<SignedEventMessage>>,
    pub escrow_sigs: Vec<SignedEventMessage>,
    signer: Signer,
    pub other_instances: HashMap<String, IdentifierState>,
}
impl LogState {
    // incept a state and keys
    pub fn new() -> Result<LogState, Error> {
        let signer = Signer::new(Basic::Ed25519)?;

        let icp_data = InceptionEvent {
            key_config: KeyConfig {
                threshold: 1,
                public_keys: vec![signer.public_key()],
                threshold_key_digest: SelfAddressing::Blake3_256
                    .derive(signer.next_public_key().to_str().as_bytes()),
            },
            witness_config: InceptionWitnessConfig::default(),
            inception_configuration: vec![],
        };

        let icp_data_message = EventMessage::get_inception_data(
            &icp_data,
            SelfAddressing::Blake3_256,
            &SerializationFormats::JSON,
        );

        let pref = IdentifierPrefix::SelfAddressing(
            SelfAddressing::Blake3_256.derive(&dfs_serializer::to_vec(&icp_data_message)?),
        );

        let icp_m = Event {
            prefix: pref.clone(),
            sn: 0,
            event_data: EventData::Icp(icp_data),
        }
        .to_message(&SerializationFormats::JSON)?;

        let sigged = icp_m.sign(vec![signer.sign(icp_m.serialize()?)?]);

        let s0 = IdentifierState::default().verify_and_apply(&sigged)?;

        Ok(LogState {
            log: vec![sigged],
            receipts: HashMap::new(),
            state: s0,
            signer,
            escrow_sigs: vec![],
            other_instances: HashMap::new(),
        })
    }

    // take a receipt made by validator, verify it and add to receipts or escrow
    pub fn add_sig(
        &mut self,
        validator: &IdentifierState,
        sigs: SignedEventMessage,
    ) -> Result<(), Error> {
        match sigs.event_message.event.event_data.clone() {
            EventData::Vrc(rct) => {
                let event = self
                    .log
                    .get(sigs.event_message.event.sn as usize)
                    .ok_or(Error::SemanticError("incorrect receipt sn".into()))?;

                // This logic can in future be moved to the correct place in the Kever equivalent here
                // receipt pref is the ID who made the event being receipted
                if sigs.event_message.event.prefix == self.state.prefix
                            // dig is the digest of the event being receipted
                            && rct.receipted_event_digest
                                == rct
                                    .receipted_event_digest
                                    .derivation
                                    .derive(&event.event_message.serialize()?)
                            // seal pref is the pref of the validator
                            && rct.validator_location_seal.prefix == validator.prefix
                {
                    if rct.validator_location_seal.event_digest
                        == rct
                            .validator_location_seal
                            .event_digest
                            .derivation
                            .derive(&validator.last)
                    {
                        // seal dig is the digest of the last establishment event for the validator, verify the rct
                        validator.verify(&event.event_message.sign(sigs.signatures.clone()))?;
                        self.receipts
                            .entry(sigs.event_message.event.sn)
                            .or_insert_with(|| vec![])
                            .push(sigs);
                    } else {
                        // escrow the seal
                        self.escrow_sigs.push(sigs)
                    }
                    Ok(())
                } else {
                    Err(Error::SemanticError("incorrect receipt binding".into()))
                }
            }
            _ => Err(Error::SemanticError("not a receipt".into())),
        }
    }

    pub fn make_rct(&self, event: EventMessage) -> Result<SignedEventMessage, Error> {
        let ser = event.serialize()?;
        Ok(Event {
            prefix: event.event.prefix,
            sn: event.event.sn,
            event_data: EventData::Vrc(ReceiptTransferable {
                receipted_event_digest: SelfAddressing::Blake3_256.derive(&ser),
                validator_location_seal: EventSeal {
                    prefix: self.state.prefix.clone(),
                    event_digest: SelfAddressing::Blake3_256.derive(&self.state.last),
                },
            }),
        }
        .to_message(&SerializationFormats::JSON)?
        .sign(vec![self.signer.sign(ser)?]))
    }

    pub fn rotate(&mut self) -> Result<SignedEventMessage, Error> {
        self.signer = self.signer.rotate()?;
        let ev = Event {
            prefix: self.state.prefix.clone(),
            sn: self.state.sn + 1,
            event_data: EventData::Rot(RotationEvent {
                previous_event_hash: SelfAddressing::Blake3_256.derive(&self.state.last),
                key_config: KeyConfig {
                    threshold: 1,
                    public_keys: vec![self.signer.public_key()],
                    threshold_key_digest: SelfAddressing::Blake3_256
                        .derive(self.signer.next_public_key().to_str().as_bytes()),
                },
                witness_config: WitnessConfig::default(),
                data: vec![],
            }),
        }
        .to_message(&SerializationFormats::JSON)?;

        let rot = ev.sign(vec![self.signer.sign(ev.serialize()?)?]);

        self.state = self.state.clone().verify_and_apply(&rot)?;

        self.log.push(rot.clone());

        Ok(rot)
    }

    pub fn make_ixn(&mut self, payload: &str) -> Result<SignedEventMessage, Error> {
        let dig_seal = DigestSeal {
            dig: SelfAddressing::Blake3_256.derive(payload.as_bytes()),
        };

        let ev = Event {
            prefix: self.state.prefix.clone(),
            sn: self.state.sn + 1,
            event_data: EventData::Ixn(InteractionEvent {
                previous_event_hash: SelfAddressing::Blake3_256.derive(&self.state.last),
                data: vec![Seal::Digest(dig_seal)],
            }),
        }
        .to_message(&SerializationFormats::JSON)?;

        let ixn = ev.sign(vec![self.signer.sign(ev.serialize()?)?]);

        self.state = self.state.clone().verify_and_apply(&ixn)?;
        self.log.push(ixn.clone());
        Ok(ixn)
    }

    pub fn process_events(&mut self, msg: Vec<u8>) -> Vec<SignedEventMessage> {
        let events = signed_event_stream(from_utf8(&msg).unwrap()).unwrap().1;
        let mut response: Vec<SignedEventMessage> = vec![];
        for ev in events {
            match ev.event_message.event.event_data {
                EventData::Vrc(ref vrc) => {
                    println!(
                        "------\n{} received receipt:\n{}",
                        self.state.prefix.to_str(),
                        from_utf8(&ev.serialize().unwrap()).unwrap()
                    );
                    let prefix_str = vrc.validator_location_seal.prefix.to_str();
                    let validator = &self.other_instances.get(&prefix_str).unwrap().clone();
                    self.add_sig(validator, ev).unwrap();
                    println!(
                        "------\nnew local state: {}\n",
                        to_string_pretty(&self.state).unwrap()
                    );
                }
                _ => {
                    println!(
                        "------\n{} received event:\n{}",
                        self.state.prefix.to_str(),
                        from_utf8(&ev.serialize().unwrap()).unwrap()
                    );

                    let prefix_str = ev.event_message.event.prefix.to_str();

                    let state = self
                        .other_instances
                        .remove(&prefix_str)
                        .unwrap_or(IdentifierState::default());
                    self.other_instances
                        .insert(prefix_str.clone(), state.verify_and_apply(&ev).unwrap());

                    println!(
                        "------\nnew remote state: {}\n",
                        to_string_pretty(&self.other_instances.get(&prefix_str)).unwrap()
                    );
                    // send receipt
                    let rct = self.make_rct(ev.event_message).unwrap();
                    let rct_s = rct.serialize().unwrap();
                    println!(
                        "------\n{} sending receipt: \n{}",
                        self.state.prefix.to_str(),
                        from_utf8(&rct_s).unwrap()
                    );
                    response.push(rct);
                }
            }
        }
        response
    }
}
