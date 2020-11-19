use std::{collections::HashMap, str::from_utf8};

use crate::{
    derivation::basic::Basic,
    derivation::self_addressing::SelfAddressing,
    derivation::self_signing::SelfSigning,
    error::Error,
    event::event_data::inception::InceptionEvent,
    event::{
        event_data::interaction::InteractionEvent,
        sections::{
            seal::{DigestSeal, Seal},
            WitnessConfig,
        },
    },
    event::{
        event_data::receipt::ReceiptTransferable, event_data::rotation::RotationEvent,
        sections::seal::EventSeal,
    },
    event::{
        event_data::EventData,
        sections::{nxt_commitment, InceptionWitnessConfig, KeyConfig},
        Event, EventMessage, SerializationFormats,
    },
    event_message::parse::signed_event_stream,
    event_message::SignedEventMessage,
    log::EventLog,
    prefix::AttachedSignaturePrefix,
    prefix::IdentifierPrefix,
    prefix::Prefix,
    signer::CryptoBox,
    state::IdentifierState,
    util::dfs_serializer,
};
mod test;
pub struct Keri {
    key_manager: CryptoBox,
    kel: EventLog,
    state: IdentifierState,
    receipts: HashMap<u64, Vec<SignedEventMessage>>,
    escrow_sigs: Vec<SignedEventMessage>,
    other_instances: HashMap<String, IdentifierState>,
}
impl Keri {
    // incept a state and keys
    pub fn new() -> Result<Keri, Error> {
        let key_manager = CryptoBox::new()?;


        let icp = InceptionEvent::new(
            KeyConfig::new(
                vec![Basic::Ed25519.derive(key_manager.public_key())],
                nxt_commitment(
                    1,
                    &[Basic::Ed25519.derive(key_manager.next_pub_key.clone())],
                    SelfAddressing::Blake3_256,
                ),
                Some(1),
            ),
            None,
            None,
        )
        .incept_self_addressing(SelfAddressing::Blake3_256, SerializationFormats::JSON)?;

        let sigged = icp.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            key_manager.sign(&icp.serialize()?)?,
            0,
        )]);
        let mut log = EventLog::new();

        let s0 = IdentifierState::default().verify_and_apply(&sigged)?;
        log.commit(sigged)?;

        Ok(Keri {
            kel: log,
            receipts: HashMap::new(),
            state: s0,
            key_manager,
            escrow_sigs: vec![],
            other_instances: HashMap::new(),
        })
    }

    pub fn rotate(&mut self) -> Result<SignedEventMessage, Error> {
        self.key_manager = self.key_manager.rotate()?;

        let ev = {
            Event {
                prefix: self.state.prefix.clone(),
                sn: self.state.sn + 1,
                event_data: EventData::Rot(RotationEvent {
                    previous_event_hash: SelfAddressing::Blake3_256.derive(&self.state.last),
                    key_config: KeyConfig::new(
                        vec![Basic::Ed25519.derive(self.key_manager.public_key())],
                        nxt_commitment(
                            1,
                            &[Basic::Ed25519.derive(self.key_manager.next_pub_key.clone())],
                            SelfAddressing::Blake3_256,
                        ),
                        Some(1),
                    ),
                    witness_config: WitnessConfig::default(),
                    data: vec![],
                }),
            }
            .to_message(SerializationFormats::JSON)?
        };

        let signature = self.key_manager.sign(&ev.serialize()?)?;
        let rot = ev.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )]);

        self.state = self.state.clone().verify_and_apply(&rot)?;

        self.kel.commit(rot.clone())?;

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
        .to_message(SerializationFormats::JSON)?;

        let signature = self.key_manager.sign(&ev.serialize()?)?;
        let ixn = ev.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )]);

        self.state = self.state.clone().verify_and_apply(&ixn)?;
        self.kel.commit(ixn.clone())?;
        Ok(ixn)
    }

    pub fn process_events(&mut self, msg: &[u8]) -> Result<String, Error> {
        let events = signed_event_stream(msg)
            .map_err(|_| Error::DeserializationError)?
            .1;
        let mut response: Vec<SignedEventMessage> = vec![];
        for ev in events {
            match ev.event_message.event.event_data {
                EventData::Vrc(ref rct) => {
                    let prefix_str = rct.validator_location_seal.prefix.to_str();
                    let validator = self.other_instances.get(&prefix_str).unwrap().clone();

                    self.process_receipt(validator, ev).unwrap();
                }
                EventData::Icp(_) => {
                    let ev_prefix = ev.event_message.event.prefix.to_str();
                    let state = IdentifierState::default().verify_and_apply(&ev)?;

                    if !self.other_instances.contains_key(&ev_prefix) {
                        if let Some(icp) = self.kel.get_last() {
                            response.push(icp);
                        }
                    }
                    self.other_instances.insert(ev_prefix.clone(), state);
                    let rct = self.make_rct(ev.event_message)?;
                    response.push(rct);
                }
                _ => {
                    let prefix_str = ev.event_message.event.prefix.to_str();

                    let state = self
                        .other_instances
                        .remove(&prefix_str)
                        .unwrap_or(IdentifierState::default());
                    self.other_instances
                        .insert(prefix_str.clone(), state.verify_and_apply(&ev)?);

                    let rct = self.make_rct(ev.event_message)?;
                    response.push(rct);
                }
            }
        }
        let str_res = response
            .iter()
            .map(|ev| from_utf8(&ev.serialize().unwrap()).unwrap().to_string())
            .collect::<Vec<_>>()
            .concat();
        Ok(str_res)
    }

    // take a receipt made by validator, verify it and add to receipts or escrow
    fn process_receipt(
        &mut self,
        validator: IdentifierState,
        sigs: SignedEventMessage,
    ) -> Result<(), Error> {
        match sigs.event_message.event.event_data.clone() {
            EventData::Vrc(rct) => {
                let event = self.kel.get(sigs.event_message.event.sn)?;

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

    fn make_rct(&self, event: EventMessage) -> Result<SignedEventMessage, Error> {
        let ser = event.serialize()?;
        let signature = self.key_manager.sign(&ser)?;
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
        .to_message(SerializationFormats::JSON)?
        .sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )]))
    }

    pub fn get_last_event(&self) -> String {
        match self.kel.get_last() {
            Some(ev) => from_utf8(&ev.serialize().unwrap()).unwrap().to_string(),
            None => String::new(),
        }
    }

    pub fn get_log_len(&self) -> usize {
        self.kel.get_len()
    }

    pub fn get_state(&self) -> IdentifierState {
        self.state.clone()
    }
}
