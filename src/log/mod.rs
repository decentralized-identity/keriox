use crate::{
    error::Error,
    event_message::VersionedEventMessage,
    state::{EventSemantics, IdentifierState, Verifiable},
};

pub struct EventLog(Vec<VersionedEventMessage>);

impl EventLog {
    pub fn new() -> Self {
        EventLog(Vec::<VersionedEventMessage>::new())
    }

    // run the validation engine on this EventLog
    pub fn replay(&self) -> Result<IdentifierState, Error> {
        replay(&self.0)
    }

    // evaluate the application of the event on this EventLog (non-mutating)
    pub fn apply(&self, event: &VersionedEventMessage) -> Result<IdentifierState, Error> {
        event.apply_to(self.replay()?)
    }

    // evaluate and APPEND the event to this EventLog
    pub fn commit(&mut self, event: VersionedEventMessage) -> Result<IdentifierState, Error> {
        let result = self.apply(&event)?;
        self.0.push(event);
        Ok(result)
    }
}

// apply every event in a KEL starting with inception
pub fn replay<T: EventSemantics + Verifiable>(kel: &[T]) -> Result<IdentifierState, Error> {
    kel.iter()
        .fold(Ok(IdentifierState::default()), |state, event| {
            state?.verify_and_apply(event)
        })
}
