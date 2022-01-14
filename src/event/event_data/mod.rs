pub mod delegated;
pub mod inception;
pub mod interaction;
pub mod rotation;

use crate::{
    error::Error,
    event_message::{EventTypeTag, Typeable},
    state::{EventSemantics, IdentifierState},
};
use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::Value;

pub use self::{
    delegated::DelegatedInceptionEvent, inception::InceptionEvent, interaction::InteractionEvent,
    rotation::RotationEvent,
};

/// Event Data
///
/// Event Data conveys the semantic content of a KERI event.
#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(untagged, rename_all = "lowercase")]
pub enum EventData {
    Icp(InceptionEvent),
    Rot(RotationEvent),
    Ixn(InteractionEvent),
    Dip(DelegatedInceptionEvent),
    Drt(RotationEvent),
}

impl<'de> Deserialize<'de> for EventData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Helper struct for adding tag to properly deserialize 't' field
        #[derive(Deserialize)]
        struct EventType {
            t: EventTypeTag,
        }

        let v = Value::deserialize(deserializer)?;
        let m = EventType::deserialize(&v).map_err(de::Error::custom)?;
        match m.t {
            EventTypeTag::Icp => Ok(EventData::Icp(
                InceptionEvent::deserialize(&v).map_err(de::Error::custom)?,
            )),
            EventTypeTag::Rot => Ok(EventData::Rot(
                RotationEvent::deserialize(&v).map_err(de::Error::custom)?,
            )),
            EventTypeTag::Ixn => Ok(EventData::Ixn(
                InteractionEvent::deserialize(&v).map_err(de::Error::custom)?,
            )),
            EventTypeTag::Dip => Ok(EventData::Dip(
                DelegatedInceptionEvent::deserialize(&v).map_err(de::Error::custom)?,
            )),
            EventTypeTag::Drt => Ok(EventData::Drt(
                RotationEvent::deserialize(&v).map_err(de::Error::custom)?,
            )),
            _ => Err(Error::SemanticError("Not a key event".into())).map_err(de::Error::custom)?,
        }
    }
}

impl EventSemantics for EventData {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        match self {
            Self::Icp(e) => e.apply_to(state),
            Self::Rot(e) => e.apply_to(state),
            Self::Ixn(e) => e.apply_to(state),
            Self::Dip(e) => e.apply_to(state),
            Self::Drt(e) => e.apply_to(state),
        }
    }
}

impl From<EventData> for EventTypeTag {
    fn from(ed: EventData) -> Self {
        match ed {
            EventData::Icp(_) => EventTypeTag::Icp,
            EventData::Rot(_) => EventTypeTag::Rot,
            EventData::Ixn(_) => EventTypeTag::Ixn,
            EventData::Dip(_) => EventTypeTag::Dip,
            EventData::Drt(_) => EventTypeTag::Drt,
        }
    }
}

impl Typeable for EventData {
    fn get_type(&self) -> EventTypeTag {
        self.into()
    }
}
