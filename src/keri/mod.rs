use crate::{
    database::sled::SledEventDatabase,
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
    prefix::IdentifierPrefix,
    processor::EventProcessor,
    signer::KeyManager,
    state::IdentifierState,
};
mod test;
pub struct Keri<K: KeyManager> {
    prefix: IdentifierPrefix,
    key_manager: K,
    processor: EventProcessor,
}

impl<K: KeyManager> Keri<K> {
    // incept a state and keys
    pub fn new(db: SledEventDatabase, key_manager: K, prefix: IdentifierPrefix) -> Result<Keri<K>, Error> {
        Ok(Keri {
            prefix,
            key_manager,
            processor: EventProcessor::new(db),
        })
    }

    pub fn incept(&mut self) -> Result<SignedEventMessage, Error> {
        let icp = EventMsgBuilder::new(EventType::Inception)?
            .with_prefix(self.prefix.clone())
            .with_keys(vec![Basic::Ed25519.derive(self.key_manager.public_key())])
            .with_next_keys(vec![
                Basic::Ed25519.derive(self.key_manager.next_public_key())
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
        self.key_manager.rotate()?;

        let rot = self.make_rotation()?;
        let rot = rot.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            self.key_manager.sign(&rot.serialize()?)?,
            0,
        )]);

        self.processor
            .process(signed_message(&rot.serialize()?).unwrap().1)?;

        Ok(rot)
    }

    fn make_rotation(&self) -> Result<EventMessage, Error> {
        let state = self
            .processor
            .compute_state(&self.prefix)?
            .ok_or(Error::SemanticError("There is no state".into()))?;
        EventMsgBuilder::new(EventType::Rotation)?
            .with_prefix(self.prefix.clone())
            .with_sn(state.sn + 1)
            .with_previous_event(SelfAddressing::Blake3_256.derive(&state.last))
            .with_keys(vec![Basic::Ed25519.derive(self.key_manager.public_key())])
            .with_next_keys(vec![
                Basic::Ed25519.derive(self.key_manager.next_public_key())
            ])
            .build()
    }

    pub fn make_ixn(&mut self, payload: Option<&str>) -> Result<SignedEventMessage, Error> {
        let seal_list = match payload {
            Some(payload) => {
                vec![Seal::Digest(DigestSeal {
                    dig: SelfAddressing::Blake3_256.derive(payload.as_bytes()),
                })]
            }
            None => vec![],
        };
        let state = self
            .processor
            .compute_state(&self.prefix)?
            .ok_or(Error::SemanticError("There is no state".into()))?;

        let ev = EventMsgBuilder::new(EventType::Interaction)?
            .with_prefix(self.prefix.clone())
            .with_sn(state.sn + 1)
            .with_previous_event(SelfAddressing::Blake3_256.derive(&state.last))
            .with_seal(seal_list)
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

    pub fn respond(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let events = signed_event_stream(msg)
            .map_err(|_| Error::DeserializationError)?
            .1;
        let (processed_ok, _processed_failed): (Vec<_>, Vec<_>) = events
            .into_iter()
            .map(|event| {
                self.processor
                    .process(event.clone())
                    .and_then(|_| Ok(event))
            })
            .partition(Result::is_ok);
        let response: Vec<u8> = processed_ok
            .into_iter()
            .map(Result::unwrap)
            .map(|des_event| -> Result<Vec<u8>, Error> {
                match des_event {
                    Deserialized::Event(ev) => {
                        let mut buf = vec![];
                        if let EventData::Icp(_) = ev.event.event.event.event_data {
                            if !self.processor.has_receipt(
                                &self.prefix,
                                0,
                                &ev.event.event.event.prefix,
                            )? {
                                buf.append(
                                    &mut self
                                        .processor
                                        .get_kerl(&self.prefix)?
                                        .ok_or(Error::SemanticError("KEL is empty".into()))?,
                                )
                            }
                        }
                        buf.append(&mut self.make_rct(ev.event.event.clone())?.serialize()?);
                        Ok(buf)
                    }
                    _ => Ok(vec![]),
                }
            })
            .filter_map(|x| x.ok())
            .flatten()
            .collect();
        Ok(response)
    }

    fn make_rct(&self, event: EventMessage) -> Result<SignedEventMessage, Error> {
        let ser = event.serialize()?;
        let signature = self.key_manager.sign(&ser)?;
        let validator_event_seal = self
            .processor
            .get_last_establishment_event_seal(&self.prefix)?
            .ok_or(Error::SemanticError("No establishment event seal".into()))?;
        let rcp = Event {
            prefix: event.event.prefix,
            sn: event.event.sn,
            event_data: EventData::Vrc(ReceiptTransferable {
                receipted_event_digest: SelfAddressing::Blake3_256.derive(&ser),
                validator_seal: validator_event_seal,
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

    pub fn get_kerl(&self) -> Result<Option<Vec<u8>>, Error> {
        self.processor.get_kerl(&self.prefix)
    }

    pub fn get_state_for_prefix(
        &self,
        prefix: &IdentifierPrefix,
    ) -> Result<Option<IdentifierState>, Error> {
        self.processor.compute_state(prefix)
    }

    pub fn get_state_for_seal(&self, seal: &EventSeal) -> Result<Option<IdentifierState>, Error> {
        self.processor.compute_state_at_sn(&seal.prefix, seal.sn)
    }
}
