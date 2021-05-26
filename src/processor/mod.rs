use crate::{database::sled::SledEventDatabase, derivation::self_addressing::SelfAddressing, error::Error, event::{
        event_data::EventData,
        sections::{
            seal::{EventSeal, LocationSeal, Seal},
            KeyConfig,
        },
    }, event_message::{EventMessage, SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt, TimestampedEventMessage, parse::{Deserialized, DeserializedSignedEvent}}, prefix::{IdentifierPrefix, SelfAddressingPrefix}, state::{EventSemantics, IdentifierState}};

#[cfg(test)]
mod tests;

pub struct EventProcessor {
    db: SledEventDatabase,
}

impl EventProcessor {
    pub fn new(db: SledEventDatabase) -> Self {
        Self { db }
    }

    /// Compute State for Prefix
    ///
    /// Returns the current State associated with
    /// the given Prefix
    pub fn compute_state(&self, id: &IdentifierPrefix) -> Result<Option<IdentifierState>, Error> {
        // start with empty state
        let mut state = IdentifierState::default();
        if let Some(events) = self.db.get_events(id) {
            // we sort here to get inception first
            let mut sorted_events = events.collect::<Vec<TimestampedEventMessage>>();
            sorted_events.sort();
            for event in sorted_events {
                state = match state.apply(&event.event) {
                    Ok(s) => s,
                    // will happen when a recovery has overridden some part of the KEL,
                    // stop processing here
                    Err(_) => break
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
        if let Some(events) = self.db.get_events(id) {
            // TODO: testing approach if events come out sorted already (as they should coz of put sequence)
            for event in events
                .filter(|e| e.event.event.sn <= sn) {
                    state = state.apply(&event.event.event)?;
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
        if let Some(events) = self.db.get_events(id) {
            for event in events {
                state = state.apply(&event.event.event)?;
                // TODO: is this event.event.event stuff too ugly? =)
                last_est = match event.event.event.event_data {
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
                prefix: event.event.prefix,
                sn: event.event.sn,
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
           Some(events) => 
               Ok(Some(events.map(|event| &event.serialize().unwrap_or_default())
                .fold(vec!(), |mut accum, serialized_event| { accum.extend(serialized_event); accum }))),
            None => Ok(None)
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
        if let Some(events) = self.db.get_events(id) {
            if let Some(event) = events.find(|e| e.event.event.sn == sn) {
                match event.event.event.prefix {
                    IdentifierPrefix::SelfAddressing(p) => {
                        // if it's the event we're looking for
                        if event_digest.digest == p.digest {
                            // return the config or error if it's not an establishment event
                            return Ok(Some(match event.event.event.event_data {
                                EventData::Icp(icp) => icp.key_config,
                                EventData::Rot(rot) => rot.key_config,
                                EventData::Dip(dip) => dip.inception_data.key_config,
                                EventData::Drt(drt) => drt.rotation_data.key_config,
                                // the receipt has a binding but it's NOT an establishment event
                                _ => Err(Error::SemanticError("Receipt binding incorrect".into()))?,
                            }));
                        }
                    },
                    _ => ()
                }
            }
        }
        Ok(None)
    }

    /// Validate delegating event seal.
    ///
    /// Validates binding between delegated and delegating events. The validation
    /// is based on delegating location seal and delegated event.
    fn validate_seal(&self, seal: LocationSeal, delegated_event: &[u8]) -> Result<(), Error> {
        // Check if event of seal's prefix and sn is in db.
        if let Some(events) = self.db.get_events(&seal.prefix) {
            match events.find(|event| event.event.event.sn == seal.sn) {
                Some(event) => {
                    // Extract prior_digest and data field from delegating event.
                    let (prior_dig, data) = match event.event.event.event_data {
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
                        match events.find(|previous_event| previous_event.event.event.sn == seal.sn -1) {
                            Some(previous_event) => {
                                match previous_event.event.event.prefix {
                                    IdentifierPrefix::SelfAddressing(prefix) => 
                                        Ok(prefix.digest == seal.prior_digest.digest),
                                    _ => Err(Error::SemanticError("No event in db".into()))
                                }
                            },
                            None => return Err(Error::SemanticError("No event in db".into()))
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
                },
                None => return Err(Error::EventOutOfOrderError)
            }
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
        Ok(if let Some(receipts) = self.db .get_receipts_t(id) {
            receipts.filter(|r| r.body.event.sn.eq(&sn))
                .any(|receipt| receipt.validator_seal.event_seal.prefix.eq(validator_pref))
        } else { false })
    }

    /// Process
    ///
    /// Process a deserialized KERI message
    pub fn process(&self, data: Deserialized) -> Result<Option<IdentifierState>, Error> {
        match data {
            Deserialized::Event(e) => self.process_event(e),
            Deserialized::NontransferableRct(rct) => self.process_witness_receipt(rct),
            Deserialized::TransferableRct(rct) => self.process_validator_receipt(rct),
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
        event: DeserializedSignedEvent,
    ) -> Result<Option<IdentifierState>, Error> {
        // Log event.
        let signed_event = SignedEventMessage::new(
                &event.event.event, event.signatures);
        self.db.add_new_signed_event_message(signed_event, &event.event.event.event.prefix)?;
        // If delegated event, check its delegator seal.
        match event.event.event.event.event_data {
            EventData::Dip(dip) =>
                self.validate_seal(dip.seal, &event.event.raw),
            EventData::Drt(drt) =>
                self.validate_seal(drt.seal, &event.event.raw),
            _ => Ok(()),
        }
        .or_else(|e| {
            if let Error::EventOutOfOrderError = e {
                // FIXME: should this be signed event instead?
                self.db.add_outoforder_event(signed_event, &event.event.event.event.prefix)?
            };
            Err(e)
        })?;

        self.apply_to_state(event.event.event)
            .and_then(|new_state| {
                // match on verification result
                match new_state
                    .current
                    .verify(&event.event.raw, &event.signatures)
                    .and_then(|_result| {
                        // TODO should check if there are enough receipts and probably escrow
                        self.db.add_kel_finalized_event(signed_event, &event.event.event.event.prefix)?;
                        Ok(new_state)
                    }) {
                        Ok(state) => Ok(Some(state)),
                        Err(e) => {
                            match e {
                                Error::NotEnoughSigsError => 
                                    self.db.add_partially_signed_event(signed_event, &event.event.event.event.prefix)?,
                                Error::EventOutOfOrderError =>
                                    self.db.add_outoforder_event(signed_event, &event.event.event.event.prefix)?,
                                Error::EventDuplicateError =>
                                    self.db.add_duplicious_event(signed_event, &event.event.event.event.prefix)?,
                                _ => (),
                            };
                            Err(e)
                        },
                    }
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
            EventData::Rct(r) => {
                let seal = vrc.validator_seal.event_seal;
                if let Some(events) = self.db.get_events(&seal.prefix) {
                    match events.find(|event| event.event.event.sn == seal.sn) {
                        Some(event) => {
                            // prev .get_keys_at_event()
                            let kp = match event.event.event.event_data {
                                EventData::Dip(e) => Some(e.inception_data.key_config),
                                EventData::Drt(e) => Some(e.rotation_data.key_config),
                                EventData::Icp(e) => Some(e.key_config),
                                EventData::Rot(e) => Some(e.key_config),
                                _ => None,
                            };
                            if kp.is_some() && kp.unwrap().verify(&event.event.serialize()?, &vrc.signatures)? {
                                let(_, errors): (Vec<_>, Vec<_>) = vrc.signatures.into_iter()
                                    .map(|signature|
                                        self.db.add_receipt_t(vrc, &vrc.body.event.prefix))
                                    .partition(Result::is_ok);
                                if errors.len() != 0 {
                                    Err(Error::StorageError)
                                } else { Ok(()) }
                            } else { Ok(()) }
                        },
                        None => {
                            self.db.add_escrow_t_receipt(vrc, &vrc.body.event.prefix)?;
                            Err(Error::SemanticError("Receipt escrowed".into()))
                        }
                    }
                } else {
                    self.db.add_escrow_t_receipt(vrc, &vrc.body.event.prefix)?;
                    Err(Error::SemanticError("Receipt escrowed".into()))
                }
            },
            _ =>  Err(Error::SemanticError("incorrect receipt structure".into()))
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
            // get event which is being receipted
            EventData::Rct(r) => {
                match self
                    .db
                    .last_event_at_sn(&rct.body.event.prefix, rct.body.event.sn)
                    // return if lookup fails
                    .map_err(|_| Error::StorageError)?
                {
                    Some(event) => {
                        // verify receipts and store or discard
                        let cas_dig = SelfAddressing::Blake3_256.derive(&event);
                        for (witness, receipt) in &rct.couplets {
                            if witness.verify(&event, &receipt)? {
                                self.db
                                    .add_nt_receipt_for_event(
                                        &rct.body.event.prefix,
                                        &cas_dig,
                                        &witness,
                                        &receipt,
                                    )
                                    .map_err(|_| Error::StorageError)?;
                            };
                        }
                    }
                    None => {
                        for (witness, receipt) in rct.couplets {
                            self.db
                                .escrow_nt_receipt(
                                    &rct.body.event.prefix,
                                    // TODO THIS MAY NOT ALWAYS MATCH, see issue #74 in dif/keri
                                    &r.receipted_event_digest,
                                    &witness,
                                    &receipt,
                                )
                                .map_err(|_| Error::StorageError)?;
                        }
                    }
                };
                self.compute_state(&rct.body.event.prefix)
            }
            _ => Err(Error::SemanticError("incorrect receipt structure".into())),
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
}
