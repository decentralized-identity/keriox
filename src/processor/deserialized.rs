use crate::{
    error::Error, event::event_data::EventData, event::sections::KeyConfig,
    event_message::SignedEventMessage, prefix::AttachedSignaturePrefix, prefix::IdentifierPrefix,
    state::IdentifierState,
};

use super::{EventType, Processable};

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

    fn verify_event_using(&self, db_event: &[u8], validator: &KeyConfig) -> Result<bool, Error> {
        validator.verify(db_event, &self.deserialized.signatures)
    }

    fn to_event_type(&self) -> EventType {
        match self.deserialized.event_message.event.event_data {
            EventData::Icp(_) | EventData::Rot(_) | EventData::Ixn(_) => EventType::KeyEvent,
            EventData::Vrc(ref vrc) => {
                EventType::ValidatorReceiptEvent(vrc.validator_location_seal.prefix.clone())
            }
            _ => todo!(),
        }
    }

    fn check_receipt_bindings(
        &self,
        validator_last: &[u8],
        original_event: &[u8],
    ) -> Result<(), Error> {
        match self.deserialized.event_message.event.event_data {
            EventData::Vrc(ref vrc) => {
                // Check if receipted message is the same as msg in db.
                if vrc.receipted_event_digest
                    != vrc
                        .receipted_event_digest
                        .derivation
                        .derive(&original_event)
                {
                    return Err(Error::SemanticError(
                        "Event digests doesn't match".to_string(),
                    ));
                }
                // Check if seal dig is the digest of the last establishment event for the validator.
                if vrc.validator_location_seal.event_digest
                    != vrc
                        .validator_location_seal
                        .event_digest
                        .derivation
                        .derive(&validator_last)
                {
                    return Err(Error::SemanticError(
                        "Validator last establish event doesn't match".to_string(),
                    ));
                }
                Ok(())
            }
            _ => {
                return Err(Error::SemanticError("Not a receipt".to_string()));
            }
        }
    }
}
