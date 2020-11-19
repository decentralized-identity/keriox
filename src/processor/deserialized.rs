use crate::{
    error::Error, event::sections::KeyConfig, event_message::SignedEventMessage,
    prefix::AttachedSignaturePrefix, prefix::IdentifierPrefix, state::IdentifierState,
};

use super::Processable;

pub struct Deserialized<'a, M> {
    raw: &'a [u8],
    deserialized: M,
}
impl Deserialized<'_, SignedEventMessage> {
    pub fn new<'a>(
        raw: &'a [u8],
        deserialized: SignedEventMessage,
    ) -> Deserialized<'a, SignedEventMessage> {
        Deserialized {
            raw: &raw,
            deserialized,
        }
    }
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
