use crate::{database::sled::SledEventDatabase, derivation::self_addressing::SelfAddressing, error::Error, event::{EventMessage, event_data::EventData, sections::{
            seal::{EventSeal, LocationSeal, Seal},
            KeyConfig,
        }}, event_message::{
        parse::{Deserialized, DeserializedEvent, DeserializedSignedEvent},
        SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt,
        TimestampedSignedEventMessage,
    }, prefix::{IdentifierPrefix, SelfAddressingPrefix}, state::{EventSemantics, IdentifierState}};

#[cfg(test)]
mod tests;

pub struct EventProcessor<'d> {
    db: &'d SledEventDatabase,
}

impl<'d> EventProcessor<'d> {
    pub fn new(db: &'d SledEventDatabase) -> Self {
        Self { db }
    }

    /// Compute State for Prefix
    ///
    /// Returns the current State associated with
    /// the given Prefix
    pub fn compute_state(&self, id: &IdentifierPrefix) -> Result<Option<IdentifierState>, Error> {
        // start with empty state
        let mut state = IdentifierState::default();
        if let Some(events) = self.db.get_kel_finalized_events(id) {
            // we sort here to get inception first
            let mut sorted_events = events.collect::<Vec<TimestampedSignedEventMessage>>();
            sorted_events.sort();
            for event in sorted_events {
                state = match state.clone().apply(&event.event) {
                    Ok(s) => s,
                    // will happen when a recovery has overridden some part of the KEL,
                    // stop processing here
                    Err(_) => break,
                };
            }
        } else {
            // no inception event, no state
            return Ok(None);
        }
        Ok(Some(state))
    }

    /// Compute State for Prefix and sn
    ///
    /// Returns the State associated with the given
    /// Prefix after applying event of given sn.
    pub fn compute_state_at_sn(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Option<IdentifierState>, Error> {
        let mut state = IdentifierState::default();
        if let Some(events) = self.db.get_kel_finalized_events(id) {
            // TODO: testing approach if events come out sorted already (as they should coz of put sequence)
            for event in events.filter(|e| e.event.event_message.event.sn <= sn) {
                state = state.apply(&event.event.event_message)?;
            }
        } else {
            return Ok(None);
        }
        Ok(Some(state))
    }

    /// Get last establishment event seal for Prefix
    ///
    /// Returns the EventSeal of last establishment event
    /// from KEL of given Prefix.
    pub fn get_last_establishment_event_seal(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Option<EventSeal>, Error> {
        let mut state = IdentifierState::default();
        let mut last_est = None;
        if let Some(events) = self.db.get_kel_finalized_events(id) {
            for event in events {
                state = state.apply(&event.event.event_message.event)?;
                // TODO: is this event.event.event stuff too ugly? =)
                last_est = match event.event.event_message.event.event_data {
                    EventData::Icp(_) => Some(event.event),
                    EventData::Rot(_) => Some(event.event),
                    _ => last_est,
                }
            }
        } else {
            return Ok(None);
        }
        let seal = last_est.and_then(|event| {
            let event_digest = SelfAddressing::Blake3_256.derive(&event.serialize().unwrap());
            Some(EventSeal {
                prefix: event.event_message.event.prefix,
                sn: event.event_message.event.sn,
                event_digest,
            })
        });
        Ok(seal)
    }

    /// Get KERL for Prefix
    ///
    /// Returns the current validated KEL for a given Prefix
    /// FIXME: add recipe messages into the mix when those are in SLED db
    pub fn get_kerl(&self, id: &IdentifierPrefix) -> Result<Option<Vec<u8>>, Error> {
        match self.db.get_kel_finalized_events(id) {
            Some(events) => Ok(Some(
                events
                    .map(|event| event.event.serialize().unwrap_or_default())
                    .fold(vec![], |mut accum, serialized_event| {
                        accum.extend(serialized_event);
                        accum
                    }),
            )),
            None => Ok(None),
        }
    }

    /// Get keys from Establishment Event
    ///
    /// Returns the current Key Config associated with
    /// the given Prefix at the establishment event
    /// represented by sn and Event Digest
    fn get_keys_at_event(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        event_digest: &SelfAddressingPrefix,
    ) -> Result<Option<KeyConfig>, Error> {
        if let Ok(Some(event)) = self.get_event_at_sn(id, sn) {
            // if it's the event we're looking for
            if event_digest.verify_binding(&event.event.event_message.serialize()?) {
                // return the config or error if it's not an establishment event
                Ok(Some(match event.event.event_message.event.event_data {
                    EventData::Icp(icp) => icp.key_config,
                    EventData::Rot(rot) => rot.key_config,
                    EventData::Dip(dip) => dip.inception_data.key_config,
                    EventData::Drt(drt) => drt.rotation_data.key_config,
                    // the receipt has a binding but it's NOT an establishment event
                    _ => Err(Error::SemanticError("Receipt binding incorrect".into()))?,
                }))
            } else {
                Err(Error::SemanticError("Event digests doesn't match".into()))
            }
        } else {
            Err(Error::NoEventError)
        }
    }

    /// Get witness threshold at sn
    ///
    /// Returns the witness threshold associated with
    /// the given Prefix and sn.
    fn get_tally_at_sn(&self, id: &IdentifierPrefix, sn: u64) -> Result<Option<u64>, Error> {
        Ok(if let Ok(Some(state)) = self.compute_state_at_sn(id, sn) {
            Some(state.tally)
        } else {
            None
        })
    }

    /// Validate delegating event seal.
    ///
    /// Validates binding between delegated and delegating events. The validation
    /// is based on delegating location seal and delegated event.
    fn validate_seal(&self, seal: LocationSeal, delegated_event: &[u8]) -> Result<(), Error> {
        // Check if event of seal's prefix and sn is in db.
        if let Ok(Some(event)) = self.get_event_at_sn(&seal.prefix, seal.sn) {
            // Extract prior_digest and data field from delegating event.
            let (prior_dig, data) = match event.event.event_message.event.event_data {
                EventData::Rot(rot) => (rot.previous_event_hash, rot.data),
                EventData::Ixn(ixn) => (ixn.previous_event_hash, ixn.data),
                EventData::Drt(drt) => (
                    drt.rotation_data.previous_event_hash,
                    drt.rotation_data.data,
                ),
                _ => return Err(Error::SemanticError("Improper event type".to_string())),
            };

            // Check if prior event digest matches prior event digest from
            // the seal.
            if prior_dig.derivation == seal.prior_digest.derivation {
                Ok(prior_dig == seal.prior_digest)
            } else {
                // get previous event from db
                match self.get_event_at_sn(&seal.prefix, seal.sn - 1)? {
                    Some(previous_event) => match previous_event.event.event_message.event.prefix {
                        IdentifierPrefix::SelfAddressing(prefix) => {
                            Ok(prefix.digest == seal.prior_digest.digest)
                        }
                        _ => Err(Error::SemanticError("No event in db".into())),
                    },
                    None => return Err(Error::SemanticError("No event in db".into())),
                }
            }?;
            // Check if event seal list contains delegating event seal.
            if !data.iter().any(|s| match s {
                Seal::Event(es) => es.event_digest.verify_binding(delegated_event),
                _ => false,
            }) {
                return Err(Error::SemanticError(
                    "Data field doesn't contain delegating event seal.".to_string(),
                ));
            };
        } else {
            return Err(Error::EventOutOfOrderError);
        }
        Ok(())
    }

    pub fn has_receipt(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        validator_pref: &IdentifierPrefix,
    ) -> Result<bool, Error> {
        Ok(if let Some(receipts) = self.db.get_receipts_t(id) {
            receipts
                .filter(|r| r.body.event.sn.eq(&sn))
                .any(|receipt| receipt.validator_seal.event_seal.prefix.eq(validator_pref))
        } else {
            false
        })
    }

    /// Process
    ///
    /// Process a deserialized KERI message
    pub fn process(&self, data: Deserialized) -> Result<Option<IdentifierState>, Error> {
        match data {
            Deserialized::Event(ev) => self
                .process_event(&ev)
                // If processing failed, check the error and escrow event properly.
                .map_err(|error| {
                    let signed_event: SignedEventMessage = ev.to_owned().into();
                    let prefix = ev.to_owned().event.event.event.prefix;
                    let out = match error {
                        Error::EventOutOfOrderError => {
                            self.db.add_outoforder_event(signed_event, &prefix)
                        }
                        Error::NotEnoughSigsError => {
                            self.db.add_partially_signed_event(signed_event, &prefix)
                        }

                        Error::EventDuplicateError => {
                            self.db.add_duplicious_event(signed_event, &prefix)
                        }
                        _ => Ok(()),
                    };
                    match out {
                        Ok(_) => error,
                        Err(e) => e,
                    }
                }),
            Deserialized::NontransferableRct(rct) => self.process_witness_receipt(rct),
            Deserialized::TransferableRct(rct) => {
                match self.process_validator_receipt(rct.clone()) {
                    Ok(p) => Ok(p),
                    Err(e) => {
                        match e {
                            Error::NoEventError => {
                                self.db
                                    .add_escrow_t_receipt(rct.to_owned(), &rct.body.event.prefix)?;
                            }
                            _ => {}
                        };
                        Err(e)
                    }
                }
            }
        }
    }

    /// Process Event
    ///
    /// Validates a Key Event against the latest state
    /// of the Identifier and applies it to update the state
    /// returns the updated state
    /// TODO improve checking and handling of errors!
    /// FIXME: refactor to remove multiple event recourse wrappers
    pub fn process_event(
        &self,
        event: &DeserializedSignedEvent,
    ) -> Result<Option<IdentifierState>, Error> {
        // Log event.
        let signed_event = SignedEventMessage::new(&event.event.event, event.signatures.clone());
        // If delegated event, check its delegator seal.
        match event.event.event.event.event_data.clone() {
            EventData::Dip(dip) => self.validate_seal(dip.seal, &event.event.raw),
            EventData::Drt(drt) => self.validate_seal(drt.seal, &event.event.raw),
            _ => Ok(()),
        }?;
        self.apply_to_state(event.event.event.clone())
            .and_then(|new_state| {
                new_state
                    .current
                    .verify(&event.event.raw, &event.signatures)
                    .and_then(|_result| {
                        // TODO should check if there are enough receipts and probably escrow
                        self.db.add_kel_finalized_event(
                            signed_event.clone(),
                            &event.event.event.event.prefix,
                        )?;
                        Ok(Some(new_state))
                    })
            })
    }

    /// Process Validator Receipt
    ///
    /// Checks the receipt against the receipted event
    /// and the state of the validator, returns the state
    /// of the identifier being receipted
    /// TODO improve checking and handling of errors!
    pub fn process_validator_receipt(
        &self,
        vrc: SignedTransferableReceipt,
    ) -> Result<Option<IdentifierState>, Error> {
        match &vrc.body.event.event_data {
            EventData::Rct(_r) => {
                if let Ok(Some(event)) =
                    self.get_event_at_sn(&vrc.body.event.prefix, vrc.body.event.sn)
                {
                    // prev .get_keys_at_event()
                    let kp = self.get_keys_at_event(
                        &vrc.validator_seal.event_seal.prefix,
                        vrc.validator_seal.event_seal.sn,
                        &vrc.validator_seal.event_seal.event_digest,
                    )?;
                    if kp.is_some()
                        && kp
                            .unwrap()
                            .verify(&event.event.event_message.serialize()?, &vrc.signatures)?
                    {
                        self.db.add_receipt_t(vrc.clone(), &vrc.body.event.prefix)
                    } else {
                        Err(Error::SemanticError("Incorrect receipt signatures".into()))
                    }
                } else {
                    Err(Error::NoEventError)
                }
            }
            _ => Err(Error::SemanticError("incorrect receipt structure".into())),
        }?;
        self.compute_state(&vrc.body.event.prefix)
    }

    /// Process Witness Receipt
    ///
    /// Checks the receipt against the receipted event
    /// returns the state of the Identifier being receipted,
    /// which may have been updated by un-escrowing events
    /// TODO improve checking and handling of errors!
    pub fn process_witness_receipt(
        &self,
        rct: SignedNontransferableReceipt,
    ) -> Result<Option<IdentifierState>, Error> {
        // check structure is correct
        match &rct.body.event.event_data {
            EventData::Rct(receipt) => {
                // get event which is being receipted
                let id = &rct.body.event.prefix.to_owned();
                if let Ok(Some(event)) =
                    self.get_event_at_sn(&rct.body.event.prefix, rct.body.event.sn)
                {
                    match event.event.event_message.event.event_data.clone() {
                        EventData::Rct(event_receipt) => {
                            if event_receipt.receipted_event_digest.digest != receipt.receipted_event_digest.digest {
                                return Err(Error::SemanticError("receipt digest missmatch event digest".into()));
                            }
                            let serialized_event = event.event.serialize()?;
                            let tally = self.get_tally_at_sn(&rct.body.event.prefix, rct.body.event.sn)?;

                            rct.verify(tally.unwrap(), &serialized_event)?;
                            self.db.add_receipt_nt(rct, &id)?
                        },
                        _ => { return Err(Error::SemanticError("incorrect receipt structure".into())); }
                    }
                } else {
                    self.db.add_escrow_nt_receipt(rct, &id)?
                }
                self.compute_state(&id)
            }
            _ => Err(Error::SemanticError("incorrect receipt structure".into())),
        }
    }

    pub fn get_event_at_sn(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Option<TimestampedSignedEventMessage>, Error> {
        if let Some(mut events) = self.db.get_kel_finalized_events(id) {
            Ok(events.find(|event| event.event.event_message.event.sn == sn))
        } else {
            Ok(None)
        }
    }

    fn apply_to_state(&self, event: EventMessage) -> Result<IdentifierState, Error> {
        // get state for id (TODO cache?)
        self.compute_state(&event.event.prefix)
            // get empty state if there is no state yet
            .and_then(|opt| Ok(opt.map_or_else(|| IdentifierState::default(), |s| s)))
            // process the event update
            .and_then(|state| event.apply_to(state))
    }

    /// Process escrow.
    ///
    /// Process any escrow entry related to event identified by Identifier
    /// prefix and sn that can be now finalized.
    pub fn process_escrow(&self, pref: &IdentifierPrefix, sn: u64) -> Result<(), Error> {
        self.process_transferable_receipts_escrow(pref, sn)?;
        self.process_outoforder_escrow(pref, sn)
    }

    fn process_outoforder_escrow(&self, pref: &IdentifierPrefix, sn: u64) -> Result<(), Error> {
        // Get receipt from escrow
        let escrowed_receipt: Vec<TimestampedSignedEventMessage> = self
            .db
            .get_outoforder_events(pref)
            .ok_or(Error::NoEventError)?
            .into_iter()
            .filter(|ev| ev.event.event_message.event.sn == sn)
            .collect();
        for escrowed in escrowed_receipt {
            let des_event = DeserializedSignedEvent {
                event: DeserializedEvent {
                    event: escrowed.event.event_message.clone(),
                    raw: &escrowed.event.serialize()?,
                },
                signatures: escrowed.event.signatures,
            };
            // FIXME: process_event should work with events, not Deserialized
            // DeserializedEvents should be removed
            match self.process_event(&des_event) {
                Ok(_) => {
                    // Event processed succesfully, remove it from escrow
                    let dig = SelfAddressing::Blake3_256
                        .derive(&escrowed.event.event_message.serialize()?);
                    self.db.remove_escrow_outoforder(pref, dig)?;
                }
                Err(e) => {
                    // Event should stay in escrow.
                }
            };
        }

        Ok(())
    }

    fn process_transferable_receipts_escrow(
        &self,
        pref: &IdentifierPrefix,
        sn: u64,
    ) -> Result<(), Error> {
        // Get receipt from escrow
        let escrowed_receipt = self
            .db
            .get_escrow_t_receipts(pref)
            .ok_or(Error::NoEventError)?
            .into_iter()
            .find(|ev| ev.body.event.sn == sn)
            .ok_or(Error::NoEventError)?;
        match self.process_validator_receipt(escrowed_receipt) {
            Ok(_) => {
                // Event processed succesfully, remove it from escrow
                self.db.remove_escrowed_trans_rct(pref, sn)?;
            }
            Err(e) => {
                // Event should stay in escrow.
            }
        };

        Ok(())
    }
}
