use crate::{
    error::Error,
    event::{event_data::EventData, sections::seal::SourceSeal, Event},
    prefix::{AttachedSignaturePrefix, IdentifierPrefix, SelfAddressingPrefix},
    state::{EventSemantics, IdentifierState},
};

use super::{
    dummy_event::{dummy_prefix, DummyEventMessage, DummyInceptionEvent},
    signed_event_message::SignedEventMessage,
    Digestible, EventMessage, SaidEvent, Typeable,
};

pub type KeyEvent = SaidEvent<Event>;

impl KeyEvent {
    pub fn get_sn(&self) -> u64 {
        self.content.sn
    }
    pub fn get_prefix(&self) -> IdentifierPrefix {
        self.content.prefix.clone()
    }
    pub fn get_event_data(&self) -> EventData {
        self.content.event_data.clone()
    }
}

impl EventSemantics for KeyEvent {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        self.content.apply_to(state)
    }
}

impl From<EventMessage<KeyEvent>> for DummyEventMessage<Event> {
    fn from(em: EventMessage<KeyEvent>) -> Self {
        DummyEventMessage {
            serialization_info: em.serialization_info,
            event_type: em.event.get_type(),
            digest: dummy_prefix(&em.event.get_digest().derivation),
            data: em.event.content,
        }
    }
}

impl EventMessage<KeyEvent> {
    pub fn sign(
        &self,
        sigs: Vec<AttachedSignaturePrefix>,
        delegator_seal: Option<SourceSeal>,
    ) -> SignedEventMessage {
        SignedEventMessage::new(self, sigs, delegator_seal)
    }

    pub fn check_digest(&self, sai: &SelfAddressingPrefix) -> Result<bool, Error> {
        let self_dig = self.event.get_digest();
        if self_dig.derivation == sai.derivation {
            Ok(&self_dig == sai)
        } else {
            Ok(sai.verify_binding(&self.to_derivation_data()?))
        }
    }

    fn to_derivation_data(&self) -> Result<Vec<u8>, Error> {
        Ok(match self.event.get_event_data() {
            EventData::Icp(icp) => DummyInceptionEvent::dummy_inception_data(
                icp,
                &self.event.get_digest().derivation,
                self.serialization_info.kind,
            )?
            .serialize()?,
            EventData::Dip(dip) => DummyInceptionEvent::dummy_delegated_inception_data(
                dip,
                &self.event.get_digest().derivation,
                self.serialization_info.kind,
            )?
            .serialize()?,
            _ => {
                let dummy_event: DummyEventMessage<_> = self.clone().into();
                dummy_event.serialize()?
            }
        })
    }
}

impl EventSemantics for EventMessage<KeyEvent> {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        let check_event_digest = |ev: &EventMessage<KeyEvent>| -> Result<(), Error> {
            ev.check_digest(&self.get_digest())?
                .then(|| ())
                .ok_or(Error::IncorrectDigest)
        };
        // Update state.last with serialized current event message.
        match self.event.get_event_data() {
            EventData::Icp(_) | EventData::Dip(_) => {
                if verify_identifier_binding(self)? {
                    self.event.apply_to(IdentifierState {
                        last_event_digest: self.get_digest(),
                        ..state
                    })
                } else {
                    Err(Error::SemanticError(
                        "Invalid Identifier Prefix Binding".into(),
                    ))
                }
            }
            EventData::Rot(ref rot) => {
                check_event_digest(self)?;
                if state.delegator.is_some() {
                    Err(Error::SemanticError(
                        "Applying non-delegated rotation to delegated state.".into(),
                    ))
                } else {
                    // Event may be out of order or duplicated, so before checking
                    // previous event hash binding and update state last, apply it
                    // to the state. It will return EventOutOfOrderError or
                    // EventDuplicateError in that cases.
                    self.event.apply_to(state.clone()).and_then(|next_state| {
                        if rot.previous_event_hash.eq(&state.last_event_digest) {
                            Ok(IdentifierState {
                                last_event_digest: self.get_digest(),
                                ..next_state
                            })
                        } else {
                            Err(Error::SemanticError(
                                "Last event does not match previous event".into(),
                            ))
                        }
                    })
                }
            }
            EventData::Drt(ref drt) => self.event.apply_to(state.clone()).and_then(|next_state| {
                check_event_digest(self)?;
                if state.delegator.is_none() {
                    Err(Error::SemanticError(
                        "Applying delegated rotation to non-delegated state.".into(),
                    ))
                } else if drt.previous_event_hash.eq(&state.last_event_digest) {
                    Ok(IdentifierState {
                        last_event_digest: self.get_digest(),
                        ..next_state
                    })
                } else {
                    Err(Error::SemanticError(
                        "Last event does not match previous event".into(),
                    ))
                }
            }),
            EventData::Ixn(ref inter) => {
                check_event_digest(self)?;
                self.event.apply_to(state.clone()).and_then(|next_state| {
                    if inter.previous_event_hash.eq(&state.last_event_digest) {
                        Ok(IdentifierState {
                            last_event_digest: self.get_digest(),
                            ..next_state
                        })
                    } else {
                        Err(Error::SemanticError(
                            "Last event does not match previous event".to_string(),
                        ))
                    }
                })
            }
        }
    }
}

pub fn verify_identifier_binding(icp_event: &EventMessage<KeyEvent>) -> Result<bool, Error> {
    let event_data = &icp_event.event.get_event_data();
    match event_data {
        EventData::Icp(icp) => match &icp_event.event.get_prefix() {
            IdentifierPrefix::Basic(bp) => Ok(icp.key_config.public_keys.len() == 1
                && bp == icp.key_config.public_keys.first().unwrap()),
            IdentifierPrefix::SelfAddressing(sap) => {
                Ok(icp_event.check_digest(sap)? && icp_event.get_digest().eq(sap))
            }
            IdentifierPrefix::SelfSigning(_ssp) => todo!(),
        },
        EventData::Dip(_dip) => match &icp_event.event.get_prefix() {
            IdentifierPrefix::SelfAddressing(sap) => icp_event.check_digest(sap),
            _ => todo!(),
        },
        _ => Err(Error::SemanticError("Not an ICP or DIP event".into())),
    }
}
