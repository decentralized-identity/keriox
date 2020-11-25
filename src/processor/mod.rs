use crate::{
    database::EventDatabase, derivation::self_addressing::SelfAddressing, error::Error,
    event::sections::KeyConfig, event_message::parse::message, prefix::AttachedSignaturePrefix,
    prefix::IdentifierPrefix, state::IdentifierState,
};

mod deserialized;

#[cfg(test)]
mod tests;

pub struct EventProcessor<D: EventDatabase> {
    db: D,
}

/// Event type representation used to determine processing method.
///
///`KeyEvent` needs only `KeyConfig` for verification, but
///`ValidatorReceiptEvent` needs also original event which it confirm.
pub enum EventType {
    KeyEvent,
    ValidatorReceiptEvent(IdentifierPrefix),
}

pub trait Processable {
    fn verify_using(&self, kc: &KeyConfig) -> Result<bool, Error>;

    fn verify_event_using(&self, db_event: &[u8], validator: &KeyConfig) -> Result<bool, Error>;

    fn check_receipt_bindings(
        &self,
        validator_last: &[u8],
        original_event: &[u8],
    ) -> Result<(), Error>;

    fn to_event_type(&self) -> EventType;

    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error>;

    fn id(&self) -> &IdentifierPrefix;

    fn sn(&self) -> u64;

    fn raw(&self) -> &[u8];

    fn sigs(&self) -> &[AttachedSignaturePrefix];
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
            let parsed = message(&String::from_utf8(raw).map_err(|_| Error::DeserializationError)?)
                .map_err(|_| Error::DeserializationError)?
                .1;
            // apply it to the state
            // TODO avoid .clone()
            state = match state.clone().apply(&parsed) {
                Ok(s) => s,
                // will happen when a recovery has overridden some part of the KEL,
                // stop processing here
                Err(_) => break,
            }
        }

        Ok(Some(state))
    }

    /// Process Event
    ///
    /// Verify signed event, apply it to State associated with prefix of the
    /// event and update the database. Returns updated state.
    pub fn process<E>(&self, event: &E) -> Result<IdentifierState, Error>
    where
        E: Processable,
    {
        let dig = SelfAddressing::Blake3_256.derive(event.raw());

        // Log event.
        self.db
            .log_event(event.id(), &dig, event.raw(), event.sigs())
            .map_err(|_| Error::StorageError)?;

        self.apply_to_state(event)
            // verify the signatures on the event and add it to db.
            .and_then(|state| {
                match event.to_event_type() {
                    EventType::KeyEvent => {
                        self.verify_key_event(&state, event)?;

                        // Add event to db.
                        self.db
                            .finalise_event(event.id(), event.sn(), &dig)
                            .map_err(|_| Error::StorageError)?;
                    }
                    EventType::ValidatorReceiptEvent(ref validator_prefix) => {
                        self.verify_validator_receipt(event, validator_prefix)?;

                        // Add receipt to db.
                        for sig in event.sigs() {
                            self.db
                                .add_t_receipt_for_event(event.id(), &dig, &validator_prefix, &sig)
                                .map_err(|_| Error::StorageError)?;
                        }
                    }
                }
                Ok(state)
            })
    }

    fn apply_to_state<E>(&self, event: &E) -> Result<IdentifierState, Error>
    where
        E: Processable,
    {
        let dig = SelfAddressing::Blake3_256.derive(event.raw());
        // get state for id (TODO cache?)
        self.compute_state(event.id())
            // get empty state if there is no state yet
            .and_then(|opt| Ok(opt.map_or_else(|| IdentifierState::default(), |s| s)))
            // process the event update
            .and_then(|state| event.apply_to(state))
            // see why application failed and reject or escrow accordingly
            .map_err(|e| match e {
                Error::EventOutOfOrderError => {
                    match self
                        .db
                        .escrow_out_of_order_event(event.id(), event.sn(), &dig)
                    {
                        Err(_) => Error::StorageError,
                        _ => e,
                    }
                }
                Error::EventDuplicateError => {
                    match self.db.duplicitous_event(event.id(), event.sn(), &dig) {
                        Err(_) => Error::StorageError,
                        _ => e,
                    }
                }
                _ => e,
            })
    }

    fn verify_key_event<E>(&self, state: &IdentifierState, event: &E) -> Result<bool, Error>
    where
        E: Processable,
    {
        let dig = SelfAddressing::Blake3_256.derive(event.raw());
        event
            .verify_using(&state.current)
            // escrow partially signed event
            .map_err(|e| match e {
                Error::NotEnoughSigsError => {
                    match self
                        .db
                        .escrow_partially_signed_event(event.id(), event.sn(), &dig)
                    {
                        Err(_) => Error::StorageError,
                        _ => e,
                    }
                }
                _ => e,
            })
    }

    fn verify_validator_receipt<E>(
        &self,
        event: &E,
        validator_pre: &IdentifierPrefix,
    ) -> Result<bool, Error>
    where
        E: Processable,
    {
        // Get event at sn for prefix which made receipted event.
        let event_from_db = self
            .db
            .last_event_at_sn(event.id(), event.sn())
            .map_err(|_| Error::StorageError)?
            .ok_or(Error::SemanticError("Event not yet in db".to_string()))?;

        // Get state of prefix which made receipt.
        let validator = self
            .compute_state(validator_pre)?
            .ok_or(Error::SemanticError("Validator not yet in db".to_string()))?;

        event.check_receipt_bindings(&validator.last, &event_from_db)?;
        event.verify_event_using(&event_from_db, &validator.current)
    }
}
