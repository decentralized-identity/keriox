use std::str::from_utf8;

use crate::{
    database::EventDatabase,
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
        sections::{nxt_commitment, KeyConfig},
        Event, EventMessage, SerializationFormats,
    },
    event_message::parse::signed_message,
    event_message::parse::{signed_event_stream, Deserialized},
    event_message::SignedEventMessage,
    prefix::AttachedSignaturePrefix,
    prefix::IdentifierPrefix,
    processor::EventProcessor,
    signer::CryptoBox,
    state::IdentifierState,
};
mod test;
pub struct Keri<D: EventDatabase> {
    prefix: IdentifierPrefix,
    key_manager: CryptoBox,
    processor: EventProcessor<D>,
}

impl<D: EventDatabase> Keri<D> {
    // incept a state and keys
    pub fn new(db: D, key_manager: CryptoBox, prefix: IdentifierPrefix) -> Result<Keri<D>, Error> {
        Ok(Keri {
            prefix,
            key_manager,
            processor: EventProcessor::new(db),
        })
    }

    pub fn incept(&mut self) -> Result<SignedEventMessage, Error> {
        let icp = InceptionEvent::new(
            KeyConfig::new(
                vec![Basic::Ed25519.derive(self.key_manager.public_key())],
                Some(nxt_commitment(
                    1,
                    &[Basic::Ed25519.derive(self.key_manager.next_pub_key.clone())],
                    SelfAddressing::Blake3_256,
                )),
                Some(1),
            ),
            None,
            None,
        )
        .incept_self_addressing(SelfAddressing::Blake3_256, SerializationFormats::JSON)?;

        let sigged = icp.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            self.key_manager.sign(&icp.serialize()?)?,
            0,
        )]);

        self.processor
            .process(signed_message(&sigged.serialize()?).unwrap().1)?;

        self.prefix = icp.event.prefix;

        Ok(sigged)
    }

    pub fn rotate(&mut self) -> Result<SignedEventMessage, Error> {
        self.key_manager = self.key_manager.rotate()?;
        let state = self.processor.compute_state(&self.prefix)?.unwrap();

        let ev = {
            Event {
                prefix: self.prefix.clone(),
                sn: state.sn + 1,
                event_data: EventData::Rot(RotationEvent {
                    previous_event_hash: SelfAddressing::Blake3_256.derive(&state.last),
                    key_config: KeyConfig::new(
                        vec![Basic::Ed25519.derive(self.key_manager.public_key())],
                        Some(nxt_commitment(
                            1,
                            &[Basic::Ed25519.derive(self.key_manager.next_pub_key.clone())],
                            SelfAddressing::Blake3_256,
                        )),
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

        self.processor
            .process(signed_message(&rot.serialize()?).unwrap().1)?;

        Ok(rot)
    }

    pub fn make_ixn(&mut self, payload: &str) -> Result<SignedEventMessage, Error> {
        let dig_seal = DigestSeal {
            dig: SelfAddressing::Blake3_256.derive(payload.as_bytes()),
        };
        let state = self.processor.compute_state(&self.prefix)?.unwrap();

        let ev = Event {
            prefix: self.prefix.clone(),
            sn: state.sn + 1,
            event_data: EventData::Ixn(InteractionEvent {
                previous_event_hash: SelfAddressing::Blake3_256.derive(&state.last),
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

        self.processor
            .process(signed_message(&ixn.serialize()?).unwrap().1)?;

        Ok(ixn)
    }

    pub fn process_events(&self, msg: &[u8]) -> Result<String, Error> {
        let events = signed_event_stream(msg)
            .map_err(|_| Error::DeserializationError)?
            .1;
        let mut response: Vec<Vec<u8>> = vec![];
        for dev in events {
            match dev {
                Deserialized::Event(ref ev) => match ev.event.event.event.event_data {
                    EventData::Icp(_) => {
                        let s = self.processor.compute_state(&ev.event.event.event.prefix)?;
                        if s == None && self.prefix != IdentifierPrefix::default() {
                            self.processor.process(dev.clone())?;
                            let own_kel = self.processor.get_kerl(&self.prefix)?.unwrap();
                            response.push(own_kel);

                            let rct = self.make_rct(ev.event.event.clone())?;
                            response.push(rct.serialize()?);
                        }
                    }
                    _ => {
                        let s = self.processor.process(dev.clone());
                        if s.is_ok() {
                            response.push(self.make_rct(ev.event.event.clone())?.serialize()?);
                        }
                    }
                },
                Deserialized::Vrc(_) => {
                    self.processor.process(dev.clone())?;
                }
                Deserialized::Rct(_) => todo!(),
            }
        }
        let str_res: Vec<u8> = response.into_iter().flatten().collect();
        Ok(from_utf8(&str_res).unwrap().to_string())
    }

    fn make_rct(&self, event: EventMessage) -> Result<SignedEventMessage, Error> {
        let ser = event.serialize()?;
        let signature = self.key_manager.sign(&ser)?;
        let state = self.processor.compute_state(&self.prefix)?.unwrap();
        let rcp = Event {
            prefix: event.event.prefix,
            sn: event.event.sn,
            event_data: EventData::Vrc(ReceiptTransferable {
                receipted_event_digest: SelfAddressing::Blake3_256.derive(&ser),
                validator_seal: EventSeal {
                    prefix: self.prefix.clone(),
                    sn: state.sn,
                    event_digest: SelfAddressing::Blake3_256.derive(&state.last),
                },
            }),
        }
        .to_message(SerializationFormats::JSON)?
        .sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )]);

        self.processor
            .process(signed_message(&rcp.serialize()?).unwrap().1)?;

        Ok(rcp)
    }

    pub fn get_log_len(&self) -> u64 {
        self.processor
            .compute_state(&self.prefix)
            .unwrap()
            .unwrap()
            .sn
            + 1
    }

    pub fn get_state(&self) -> Result<Option<IdentifierState>, Error> {
        self.processor.compute_state(&self.prefix)
    }

    pub fn get_state_for_prefix(
        &self,
        prefix: &IdentifierPrefix,
    ) -> Result<Option<IdentifierState>, Error> {
        self.processor.compute_state(prefix)
    }
}
