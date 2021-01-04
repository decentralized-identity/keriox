use crate::{
    database::EventDatabase,
    derivation::self_addressing::SelfAddressing,
    error::Error,
    event::{
        event_data::EventData,
        sections::{
            seal::{LocationSeal, Seal},
            KeyConfig,
        },
    },
    event_message::{
        parse::{message, Deserialized, DeserializedSignedEvent},
        EventMessage, SignedEventMessage, SignedNontransferableReceipt,
    },
    prefix::{IdentifierPrefix, SelfAddressingPrefix},
    state::{EventSemantics, IdentifierState},
};

#[cfg(test)]
mod tests;

pub struct EventProcessor<D: EventDatabase> {
    db: D,
}

impl<D: EventDatabase> EventProcessor<D> {
    pub fn new(db: D) -> Self {
        Self { db }
    }

    /// Compute State for Prefix
    ///
    /// Returns the current State associated with
    /// the given Prefix
    pub fn compute_state(&self, id: &IdentifierPrefix) -> Result<Option<IdentifierState>, Error> {
        // start with empty state
        let mut state = IdentifierState::default();

        // starting from inception
        for sn in 0.. {
            // read the latest raw event
            let raw = match self
                .db
                .last_event_at_sn(id, sn)
                .map_err(|_| Error::StorageError)?
            {
                Some(r) => r,
                None => {
                    if sn == 0 {
                        // no inception event, no state
                        return Ok(None);
                    } else {
                        // end of KEL, stop looping
                        break;
                    }
                }
            };
            // parse event
            let parsed = message(&raw).map_err(|_| Error::DeserializationError)?.1;
            // apply it to the state
            // TODO avoid .clone()
            state = match state.clone().apply(&parsed.event) {
                Ok(s) => s,
                // will happen when a recovery has overridden some part of the KEL,
                // stop processing here
                Err(_) => break,
            }
        }

        Ok(Some(state))
    }

    /// Get keys from Establishment Event
    ///
    /// Returns the current Key Config associated with
    /// the given Prefix at the establishment event
    /// represented by Event Digest
    fn get_keys_at_event(
        &self,
        id: &IdentifierPrefix,
        event_digest: &SelfAddressingPrefix,
    ) -> Result<Option<KeyConfig>, Error> {
        // starting from inception
        for sn in 0.. {
            // read the latest raw event
            let raw = match self
                .db
                .last_event_at_sn(id, sn)
                .map_err(|_| Error::StorageError)?
            {
                Some(r) => r,
                // end of KEL and no matching event found
                None => return Ok(None),
            };

            // if it's the event we're looking for
            if event_digest.verify_binding(&raw) {
                // parse event
                let parsed = message(&raw).map_err(|_| Error::DeserializationError)?.1;

                // return the config or error if it's not an establishment event
                return Ok(Some(match parsed.event.event.event_data {
                    EventData::Icp(icp) => icp.key_config,
                    EventData::Rot(rot) => rot.key_config,
                    EventData::Dip(dip) => dip.inception_data.key_config,
                    EventData::Drt(drt) => drt.rotation_data.key_config,
                    // the receipt has a binding but it's NOT an establishment event
                    _ => Err(Error::SemanticError("Receipt binding incorrect".into()))?,
                }));
            }
        }

        Ok(None)
    }

    fn validate_seal(
        &self,
        seal: LocationSeal,
        pref: &IdentifierPrefix,
        dig: &SelfAddressingPrefix,
        sn: u64,
    ) -> Result<(), Error> {
        // Check if event of seal's prefix and sn is in db.
        match self
            .db
            .last_event_at_sn(&seal.prefix, seal.sn)
            .map_err(|_| Error::StorageError)?
        {
            None => {
                // No event found, escrow delegated event.
                self.db
                    .escrow_out_of_order_event(pref, sn, dig)
                    .map_err(|_| Error::StorageError)?;
                return Err(Error::EventOutOfOrderError);
            }
            Some(del_event) => {
                // Deserialize event.
                let deserialized_event = message(&del_event)
                    .map_err(|_err| Error::SemanticError("Can't parse event".to_string()))?
                    .1;

                // Extract prior_digest and data field from delegating event.
                let (prior_dig, data) = match deserialized_event.event.event.event_data {
                    EventData::Rot(rot) => (rot.previous_event_hash, rot.data),
                    EventData::Ixn(ixn) => (ixn.previous_event_hash, ixn.data),
                    EventData::Drt(drt) => (
                        drt.rotation_data.previous_event_hash,
                        drt.rotation_data.data,
                    ),
                    _ => return Err(Error::SemanticError("Improper event type".to_string())),
                };
                // Check if previous events match.
                if prior_dig != seal.prior_digest {
                    return Err(Error::SemanticError(
                        "Prior events digests do not match.".to_string(),
                    ));
                };
                // Check if event seal list contains delegating event seal.
                if !data.iter().any(|s| match s {
                    Seal::Event(es) => &es.prefix == pref && &es.event_digest == dig,
                    _ => false,
                }) {
                    return Err(Error::SemanticError(
                        "Data field doesn't contain delegating event seal.".to_string(),
                    ));
                };
            }
        }
        Ok(())
    }

    /// Process
    ///
    /// Process a deserialized KERI message
    pub fn process(&self, data: Deserialized) -> Result<Option<IdentifierState>, Error> {
        match data {
            Deserialized::Event(e) => self.process_event(e),
            Deserialized::Vrc(r) => self.process_validator_receipt(r),
            Deserialized::Rct(r) => self.process_witness_receipt(r),
        }
    }

    /// Process Event
    ///
    /// Validates a Key Event against the latest state
    /// of the Identifier and applies it to update the state
    /// returns the updated state
    /// TODO improve checking and handling of errors!
    pub fn process_event<'a>(
        &self,
        event: DeserializedSignedEvent<'a>,
    ) -> Result<Option<IdentifierState>, Error> {
        // extract some useful info from the event for readability
        let dig = SelfAddressing::Blake3_256.derive(event.event.raw);
        let pref = &event.event.event.event.prefix.clone();
        let sn = event.event.event.event.sn;
        let ilk = event.event.event.event.event_data.clone();
        let raw = &event.event.raw;
        let sigs = event.signatures;

        // Log event.
        self.db
            .log_event(&pref, &dig, raw, &sigs)
            .map_err(|_| Error::StorageError)?;

        // If delegated event, check its delegator seal.
        match ilk {
            EventData::Dip(dip) => self.validate_seal(dip.seal, pref, &dig, sn),
            EventData::Drt(drt) => self.validate_seal(drt.seal, pref, &dig, sn),
            _ => Ok(()),
        }
        .or_else(|e| {
            if let Error::EventOutOfOrderError = e {
                self.db
                    .escrow_out_of_order_event(pref, sn, &dig)
                    .map_err(|_| Error::StorageError)?;
            };
            Err(e)
        })?;

        self.apply_to_state(event.event.event)
            .and_then(|new_state| {
                // match on verification result
                new_state
                    .current
                    .verify(raw, &sigs)
                    .and_then(|_result| {
                        // TODO should check if there are enough receipts and probably escrow
                        self.db
                            .finalise_event(pref, sn, &dig)
                            .map_err(|_| Error::StorageError)?;
                        Ok(Some(new_state))
                    })
                    .map_err(|e| match e {
                        Error::NotEnoughSigsError => {
                            match self.db.escrow_partially_signed_event(pref, sn, &dig) {
                                Ok(_) => e,
                                Err(_) => Error::StorageError,
                            }
                        }
                        _ => e,
                    })
            })
            .map_err(|e| {
                match e {
                    // see why application failed and reject or escrow accordingly
                    Error::EventOutOfOrderError => {
                        self.db.escrow_out_of_order_event(pref, sn, &dig)
                    }
                    Error::EventDuplicateError => self.db.duplicitous_event(pref, sn, &dig),
                    _ => Ok(()),
                };
                e
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
        vrc: SignedEventMessage,
    ) -> Result<Option<IdentifierState>, Error> {
        match &vrc.event_message.event.event_data {
            EventData::Vrc(r) => {
                match self
                    .db
                    .last_event_at_sn(&vrc.event_message.event.prefix, vrc.event_message.event.sn)
                    .map_err(|_| Error::StorageError)?
                {
                    // No event found, escrow the receipt
                    None => {
                        for sig in vrc.signatures {
                            self.db
                                .escrow_t_receipt(
                                    &vrc.event_message.event.prefix,
                                    &r.receipted_event_digest,
                                    &r.validator_location_seal.prefix,
                                    &sig,
                                )
                                .map_err(|_| Error::StorageError)?
                        }
                    }
                    // Event found, verify receipt and store
                    Some(event) => {
                        let keys = self
                            .get_keys_at_event(
                                &r.validator_location_seal.prefix,
                                &r.validator_location_seal.event_digest,
                            )?
                            .ok_or(Error::SemanticError("No establishment Event found".into()))?;
                        if keys.verify(&event, &vrc.signatures)? {
                            for sig in vrc.signatures {
                                self.db
                                    .add_t_receipt_for_event(
                                        &vrc.event_message.event.prefix,
                                        &SelfAddressing::Blake3_256.derive(&event),
                                        &r.validator_location_seal.prefix,
                                        &sig,
                                    )
                                    .map_err(|_| Error::StorageError);
                            }
                        } else {
                            Err(Error::SemanticError("Incorrect receipt signatures".into()))?;
                        }
                    }
                };
                self.compute_state(&vrc.event_message.event.prefix)
            }
            _ => Err(Error::SemanticError("incorrect receipt structure".into())),
        }
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
                                    .map_err(|_| Error::StorageError);
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
                                .map_err(|_| Error::StorageError);
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
