use std::{
    cell::RefCell,
    sync:: Arc,
};

use crate::{database::sled::SledEventDatabase, derivation::basic::Basic, derivation::self_addressing::SelfAddressing, derivation::self_signing::SelfSigning, error::Error, event::sections::seal::{DigestSeal, Seal}, event::{event_data::EventData, Event, EventMessage, SerializationFormats}, event::{event_data::Receipt, sections::seal::EventSeal}, event_message::{parse::signed_message, payload_size::PayloadType}, event_message::{
        event_msg_builder::{EventMsgBuilder, EventType},
        parse::{signed_event_stream, Deserialized},
    }, event_message::{SignedEventMessage, SignedTransferableReceipt}, keys::Key, prefix::AttachedSignaturePrefix, prefix::{BasicPrefix, IdentifierPrefix}, processor::EventProcessor, signer::KeyManager, state::{EventSemantics, IdentifierState}};

#[cfg(test)]
mod test;
pub struct Keri<K: KeyManager> {
    prefix: IdentifierPrefix,
    key_manager: Arc<RefCell<K>>,
    processor: EventProcessor,
}

impl<K: KeyManager> Keri<K> {
    // incept a state and keys
    pub fn new(db: Arc<SledEventDatabase>, key_manager: Arc<RefCell<K>>, prefix: IdentifierPrefix) -> Result<Keri<K>, Error> {
        Ok(Keri {
            prefix,
            key_manager,
            processor: EventProcessor::new(db),
        })
    }

    pub fn process(&self, id: &IdentifierPrefix, event: impl EventSemantics)
        -> Result<(), Error> {
            match self.processor.process_actual_event(id, event) {
                Ok(Some(_)) => Ok(()),
                Ok(None) => Err(Error::SemanticError("Unknown identifier.".into())),
                Err(e) => Err(e)
            }
        }

    pub fn incept(&mut self) -> Result<SignedEventMessage, Error> {
        let icp = EventMsgBuilder::new(EventType::Inception)?
            .with_prefix(self.prefix.clone())
            .with_keys(vec![Basic::Ed25519.derive(self.key_manager.borrow().public_key())])
            .with_next_keys(vec![
                Basic::Ed25519.derive(self.key_manager.borrow().next_public_key())
            ])
            .build()?;

        let signed = icp.sign(PayloadType::MA, vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            self.key_manager.borrow().sign(&icp.serialize()?)?,
            0,
        )]);

        self.processor
            .process(signed_message(&signed.serialize()?).unwrap().1)?;

        self.prefix = icp.event.prefix;

        Ok(signed)
    }

    /// Incepts instance of KERI and includes EXTRA keys provided as parameter
    /// CURRENT Public verification key is extracted directly from KeyManager
    ///  - it should not be included into `extra_keys` set.
    /// # Parameters
    /// * `extra_keys` - iterator over tuples of `(keri::derivation::Basic, keri::keys::Key)`
    /// # Returns
    /// `Result<keri::event_message::SignedEventMessage, keri::error::Error>`
    ///  where `SignedEventMessage` is ICP event including all provided keys + directly fetched
    ///  verification key, signed with it's private key via KeyManager and serialized.
    ///
    pub fn incept_with_extra_keys(&mut self, extra_keys: impl IntoIterator<Item = (Basic, Key)>)
        -> Result<SignedEventMessage, Error> {
            let mut keys: Vec<BasicPrefix> = extra_keys
                .into_iter()
                .map(|(key_type, key)| key_type.derive(key)).collect();
            keys.push(Basic::Ed25519.derive(self.key_manager.borrow().public_key()));
            let icp = EventMsgBuilder::new(EventType::Inception)?
                .with_prefix(self.prefix.clone())
                .with_keys(keys)
                .with_next_keys(vec!(Basic::Ed25519.derive(self.key_manager.borrow().next_public_key())))
                .build()?;

            let signed = icp.sign(PayloadType::MA, vec!(
                AttachedSignaturePrefix::new(
                    SelfSigning::Ed25519Sha512,
                    self.key_manager.borrow().sign(&icp.serialize()?)?,
                    0
                )
            ));
            let serialized = signed.serialize()?;
            println!("{}", String::from_utf8(serialized.clone()).unwrap());
            self.processor.process(signed_message(&serialized).unwrap().1)?;
            self.prefix = icp.event.prefix;

            Ok(signed)
    }

    pub fn rotate(&mut self) -> Result<SignedEventMessage, Error> {
        self.key_manager.borrow_mut().rotate()?;

        let rot = self.make_rotation()?;
        let rot = rot.sign(PayloadType::MA, vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            self.key_manager.borrow().sign(&rot.serialize()?)?,
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
            .with_keys(vec![Basic::Ed25519.derive(self.key_manager.borrow().public_key())])
            .with_next_keys(vec![
                Basic::Ed25519.derive(self.key_manager.borrow().next_public_key())
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

        let ixn = ev.sign(PayloadType::MA, vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            self.key_manager.borrow().sign(&ev.serialize()?)?,
            0,
        )]);

        self.processor
            .process(signed_message(&ixn.serialize()?).unwrap().1)?;

        Ok(ixn)
    }

    /// Process and respond to single event
    ///
    pub fn respond_single(&self, msg: &[u8]) -> Result<(IdentifierPrefix, Vec<u8>), Error> {
        match signed_message(msg) {
            Err(e) => Err(Error::DeserializeError(e.to_string())),
            Ok(event) => {
                match self.processor.process(event.1)? {
                    None => Err(Error::InvalidIdentifierStat),
                    Some(state) => Ok((state.prefix.clone(), serde_json::to_vec(&state)?)),
                }
            }
        }
    }

    pub fn respond(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let events = signed_event_stream(msg)
            .map_err(|e| Error::DeserializeError(e.to_string()))?
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
                        if let EventData::Icp(_) = ev.event.event_message.event.event_data {
                            if !self.processor.has_receipt(
                                &self.prefix,
                                0,
                                &ev.event.event_message.event.prefix,
                            )? {
                                buf.append(
                                    &mut self
                                        .processor
                                        .get_kerl(&self.prefix)?
                                        .ok_or(Error::SemanticError("KEL is empty".into()))?,
                                )
                            }
                        }
                        buf.append(&mut self.make_rct(ev.event.event_message.clone())?.serialize()?);
                        Ok(buf)
                    }
                    // TODO: this should process properly
                    _ => Ok(vec![]),
                }
            })
            .filter_map(|x| x.ok())
            .flatten()
            .collect();
        Ok(response)
    }

    fn make_rct(&self, event: EventMessage) -> Result<SignedTransferableReceipt, Error> {
        let ser = event.serialize()?;
        let signature = self.key_manager.borrow().sign(&ser)?;
        let validator_event_seal = self
            .processor
            .get_last_establishment_event_seal(&self.prefix)?
            .ok_or(Error::SemanticError("No establishment event seal".into()))?;
        let rcp = Event {
            prefix: event.event.prefix,
            sn: event.event.sn,
            event_data: EventData::Rct(Receipt {
                receipted_event_digest: SelfAddressing::Blake3_256.derive(&ser),
            }),
        }
        .to_message(SerializationFormats::JSON)?;

        let signatures = vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )];
        let signed_rcp = SignedTransferableReceipt::new(&rcp, validator_event_seal, signatures);

        self.processor
            .process(signed_message(&signed_rcp.serialize()?).unwrap().1)?;

        Ok(signed_rcp)
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
