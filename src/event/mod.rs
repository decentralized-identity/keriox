use crate::event_message::EventMessage;
use crate::prefix::{AttachedSignaturePrefix, IdentifierPrefix};
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
    #[serde(rename = "pre")]
    pub prefix: IdentifierPrefix,

    #[serde(with = "SerHex::<Compact>")]
    pub sn: u64,

    #[serde(flatten)]
    pub event_data: EventData,
}

impl Event {
    pub fn sign(&self, sigs: Vec<AttachedSignaturePrefix>) -> Result<EventMessage, Error> {
        EventMessage::new(self, sigs)
    }

    pub fn get_serialized_size(&self) -> Result<usize, Error> {
        EventMessage::get_size(self)
    }

    /// Extract Serialized Data Set
    ///
    /// returns the serialized extracted data set (for signing/verification) for this event
    /// NOTE: this automatically calculates the "vs" data
    pub fn extract_serialized_data_set(&self) -> Result<String, Error> {
        EventMessage::new(self, vec![])?.extract_serialized_data_set()
    }
}

impl EventSemantics for Event {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        match self.event_data {
            EventData::Icp(_) => {
                // ICP events require the state to be uninitialized
                if state != IdentifierState::default() || self.sn != 0 {
                    return Err(Error::SemanticError("SN is not correct".to_string()));
                }
            }
            _ => {
                // prefix must equal. sn must be incremented
                if self.prefix != state.prefix {
                    return Err(Error::SemanticError("Prefix does not match".to_string()));
                } else if self.sn != state.sn + 1 {
                    return Err(Error::SemanticError("SN is not correct".to_string()));
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
  \"pre\": \"DXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148\",
  \"sn\": \"0\",
  \"ilk\": \"icp\",
  \"sith\": 2,
  \"keys\":
  [
    \"BWoNZsa88VrTkep6HQt27fTh-4HA8tr54sHON1vWl6FE\",
    \"B8tr54sHON1vWVrTkep6H-4HAl6FEQt27fThWoNZsa88\",
    \"BVrTkep6HHA8tr54sHON1Qt27fThWoNZsa88-4vWl6FE\"
  ],
  \"nxt\": \"FWoNZsa88VrTkep6HQt27fTh-4HA8tr54sHON1vWl6FE\",
  \"toad\": 2,
  \"wits\":
  [
    \"DVrTkep6H-Qt27fThWoNZsa884HA8tr54sHON1vWl6FE\",
    \"DHON1vWl6FEQt27fThWoNZsa88VrTkep6H-4HA8tr54s\",
    \"DThWoNZsa88VrTkeQt27fp6H-4HA8tr54sHON1vWl6FE\"
  ],
  \"cnfg\": []
}";

        let event: Event = serde_json::from_str(event_str)?;

        print!("\n{}\n", serde_json::to_string(&event)?);

        Ok(())
    }
}
