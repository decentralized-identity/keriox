use std::str::from_utf8;

use crate::{
    database::EventDatabase,
    derivation::basic::Basic,
    derivation::self_addressing::SelfAddressing,
    derivation::self_signing::SelfSigning,
    error::Error,
    event::sections::seal::{DigestSeal, Seal},
    event::{event_data::receipt::ReceiptTransferable, sections::seal::EventSeal},
    event::{event_data::EventData, Event, EventMessage, SerializationFormats},
    event_message::parse::signed_message,
    event_message::SignedEventMessage,
    event_message::{
        event_msg_builder::{EventMsgBuilder, EventType},
        parse::{signed_event_stream, Deserialized},
    },
    prefix::AttachedSignaturePrefix,
    prefix::{IdentifierPrefix, Prefix},
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
        let icp = EventMsgBuilder::new(EventType::Inception)?
            .with_keys(vec![Basic::Ed25519.derive(self.key_manager.public_key())])
            .with_next_keys(vec![
                Basic::Ed25519.derive(self.key_manager.next_pub_key.clone())
            ])
            .build()?;

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
        let state = self
            .processor
            .compute_state(&self.prefix)?
            .ok_or(Error::SemanticError("There is no state".into()))?;

        let rot = EventMsgBuilder::new(EventType::Rotation)?
            .with_prefix(self.prefix.clone())
            .with_sn(state.sn + 1)
            .with_previous_event(SelfAddressing::Blake3_256.derive(&state.last))
            .with_keys(vec![Basic::Ed25519.derive(self.key_manager.public_key())])
            .with_next_keys(vec![
                Basic::Ed25519.derive(self.key_manager.next_pub_key.clone())
            ])
            .build()?;

        let rot = rot.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            self.key_manager.sign(&rot.serialize()?)?,
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
        let state = self
            .processor
            .compute_state(&self.prefix)?
            .ok_or(Error::SemanticError("There is no state".into()))?;

        let ev = EventMsgBuilder::new(EventType::Interaction)?
            .with_prefix(self.prefix.clone())
            .with_sn(state.sn + 1)
            .with_previous_event(SelfAddressing::Blake3_256.derive(&state.last))
            .with_seal(vec![Seal::Digest(dig_seal)])
            .build()?;

        let ixn = ev.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            self.key_manager.sign(&ev.serialize()?)?,
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
        let mut append_own_kel = false;
        let receipts: Vec<_> = events
            .into_iter()
            .filter(|event| self.processor.process(event.clone()).is_ok())
            .map(|des_event| {
                match des_event {
                    Deserialized::Event(ev) => {
                        if let EventData::Icp(_) = ev.event.event.event.event_data {
                            // Check for self receipt
                            // If i have receipt of mine icp, dont append own kel
                            if self.prefix != IdentifierPrefix::default() {
                                append_own_kel = true;
                            }
                        }
                        self.make_rct(ev.event.event.clone())
                            .unwrap()
                            .serialize()
                            .unwrap()
                    }
                    _ => vec![],
                }
            })
            .flatten()
            .collect();

        let out = if append_own_kel {
            vec![self.processor.get_kerl(&self.prefix)?.unwrap(), receipts]
                .into_iter()
                .flatten()
                .collect()
        } else {
            receipts
        };
        println!(
            "self id:{},\n responses to {}: \n\n {}\n\n",
            self.prefix.to_str(),
            from_utf8(msg).unwrap(),
            from_utf8(&out).unwrap()
        );
        Ok(from_utf8(&out).unwrap().to_string())
    }

    fn make_rct(&self, event: EventMessage) -> Result<SignedEventMessage, Error> {
        let ser = event.serialize()?;
        let signature = self.key_manager.sign(&ser)?;
        let state = self
            .processor
            .compute_state(&self.prefix)?
            .ok_or(Error::SemanticError("There is no state".into()))?;
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
