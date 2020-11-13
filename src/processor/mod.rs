use crate::{
    database::EventDatabase,
    derivation::self_addressing::SelfAddressing,
    error::Error,
    event::sections::KeyConfig,
    event_message::{parse::message, SignedEventMessage},
    prefix::AttachedSignaturePrefix,
    prefix::IdentifierPrefix,
    state::IdentifierState,
};

pub struct EventProcessor<D: EventDatabase> {
    db: D,
}

pub struct Deserialized<'a, M> {
    raw: &'a [u8],
    deserialized: M,
}

pub trait Processable {
    fn verify_using(&self, kc: &KeyConfig) -> Result<bool, Error>;

    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error>;

    fn id(&self) -> &IdentifierPrefix;

    fn sn(&self) -> u64;

    fn raw(&self) -> &[u8];

    fn sigs(&self) -> &[AttachedSignaturePrefix];
}

impl Processable for Deserialized<'_, SignedEventMessage> {
    fn verify_using(&self, kc: &KeyConfig) -> Result<bool, Error> {
        kc.verify(self.raw, &self.deserialized.signatures)
    }

    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        state.apply(&self.deserialized)
    }

    fn id(&self) -> &IdentifierPrefix {
        &self.deserialized.event_message.event.prefix
    }

    fn sn(&self) -> u64 {
        self.deserialized.event_message.event.sn
    }

    fn raw(&self) -> &[u8] {
        &self.raw
    }

    fn sigs(&self) -> &[AttachedSignaturePrefix] {
        &self.deserialized.signatures
    }
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
            // FIXME, DONT UNWRAP
            let parsed = message(&String::from_utf8(raw).unwrap()).unwrap().1;
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

    pub fn process<E>(&self, event: &E) -> Result<IdentifierState, Error>
    where
        E: Processable,
    {
        let dig = SelfAddressing::Blake3_256.derive(event.raw());
        self.db
            .log_event(event.id(), &dig, event.raw(), event.sigs())
            .map_err(|_| Error::StorageError)?;
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
            // verify the signatures on the event
            .and_then(|state| {
                event
                    .verify_using(&state.current)
                    // escrow partially signed event
                    .map_err(|e| match e {
                        Error::NotEnoughSigsError => {
                            match self.db.escrow_partially_signed_event(
                                event.id(),
                                event.sn(),
                                &dig,
                            ) {
                                Err(_) => Error::StorageError,
                                _ => e,
                            }
                        }
                        _ => e,
                    })?;
                self.db
                    .finalise_event(event.id(), event.sn(), &dig)
                    .map_err(|_| Error::StorageError)?;
                Ok(state)
            })
    }
}
