use crate::{
    error::Error,
    event_message::SignedEventMessage,
    state::{EventSemantics, IdentifierState, Verifiable},
};

pub struct EventLog(Vec<SignedEventMessage>);

impl EventLog {
    pub fn new() -> Self {
        EventLog(Vec::<SignedEventMessage>::new())
    }

    // run the validation engine on this EventLog
    pub fn replay(&self) -> Result<IdentifierState, Error> {
        replay(&self.0)
    }

    // evaluate the application of the event on this EventLog (non-mutating)
    pub fn apply(&self, event: &SignedEventMessage) -> Result<IdentifierState, Error> {
        event.apply_to(self.replay()?)
    }

    // evaluate and APPEND the event to this EventLog
    pub fn commit(&mut self, event: SignedEventMessage) -> Result<IdentifierState, Error> {
        let result = self.apply(&event)?;
        self.0.push(event);
        Ok(result)
    }

    pub fn get(&self, sn: u64) -> Result<&SignedEventMessage, Error> {
        self.0
            .get(sn as usize)
            .ok_or(Error::SemanticError("sn not found in log".into()))
    }

    pub fn get_last(&self) -> Option<&SignedEventMessage> {
        self.0.last()
    }

    pub fn get_len(&self) -> usize {
        self.0.len()
    }
}

// apply every event in a KEL starting with inception
pub fn replay<T: EventSemantics + Verifiable>(kel: &[T]) -> Result<IdentifierState, Error> {
    kel.iter()
        .fold(Ok(IdentifierState::default()), |state, event| {
            state?.verify_and_apply(event)
        })
}
