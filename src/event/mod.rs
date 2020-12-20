pub use crate::event_message::{serialization_info::SerializationFormats, EventMessage};
use crate::prefix::IdentifierPrefix;
use crate::state::IdentifierState;
use serde::{Deserialize, Serialize};
pub mod event_data;
pub mod sections;
use self::event_data::EventData;
use crate::error::Error;
use crate::state::EventSemantics;
use serde_hex::{Compact, SerHex};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Event {
    #[serde(rename = "i")]
    pub prefix: IdentifierPrefix,

    #[serde(rename = "s", with = "SerHex::<Compact>")]
    pub sn: u64,

    #[serde(flatten)]
    pub event_data: EventData,
}

impl Event {
    pub fn to_message(self, format: SerializationFormats) -> Result<EventMessage, Error> {
        EventMessage::new(self, format)
    }
}

impl EventSemantics for Event {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        match self.event_data {
            EventData::Icp(_) | EventData::Dip(_) => {
                // ICP events require the state to be uninitialized
                if state.prefix != IdentifierPrefix::default() {
                    return Err(Error::EventDuplicateError);
                }
                if self.sn != 0 {
                    return Err(Error::SemanticError("SN is not correct".to_string()));
                }
            }
            EventData::Vrc(_) | EventData::Rct(_) => {
                if self.prefix != state.prefix {
                    return Err(Error::SemanticError(
                        "Invalid Identifier Prefix Binding".into(),
                    ));
                }
            }
            _ => {
                // prefix must equal.
                if self.prefix != state.prefix {
                    return Err(Error::SemanticError("Prefix does not match".to_string()));
                // sn must be incremented
                // TODO recovery will break this rule when we implement it
                } else if self.sn < state.sn + 1 {
                    return Err(Error::EventDuplicateError);
                } else if self.sn > state.sn + 1 {
                    return Err(Error::EventOutOfOrderError);
                }
            }
        };
        Ok(IdentifierState {
            sn: self.sn,
            prefix: self.prefix.clone(),
            ..self.event_data.apply_to(state)?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn ser_der() -> Result<(), serde_json::Error> {
        let event_str = "{
  \"i\": \"DXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148\",
  \"s\": \"0\",
  \"t\": \"icp\",
  \"kt\": \"2\",
  \"k\":
  [
    \"BWoNZsa88VrTkep6HQt27fTh-4HA8tr54sHON1vWl6FE\",
    \"B8tr54sHON1vWVrTkep6H-4HAl6FEQt27fThWoNZsa88\",
    \"BVrTkep6HHA8tr54sHON1Qt27fThWoNZsa88-4vWl6FE\"
  ],
  \"n\": \"FWoNZsa88VrTkep6HQt27fTh-4HA8tr54sHON1vWl6FE\",
  \"wt\": \"2\",
  \"w\":
  [
    \"DVrTkep6H-Qt27fThWoNZsa884HA8tr54sHON1vWl6FE\",
    \"DHON1vWl6FEQt27fThWoNZsa88VrTkep6H-4HA8tr54s\",
    \"DThWoNZsa88VrTkeQt27fp6H-4HA8tr54sHON1vWl6FE\"
  ],
  \"c\": []
}";

        let event: Event = serde_json::from_str(event_str)?;

        print!("\n{}\n", serde_json::to_string(&event)?);

        Ok(())
    }
}
