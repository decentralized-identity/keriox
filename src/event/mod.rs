use crate::prefix::Prefix;
use crate::state::IdentifierState;
use serde::{Deserialize, Serialize};
pub mod event_data;
pub mod sections;

use self::event_data::EventData;
use self::event_data::EventSemantics;

#[derive(Serialize, Deserialize)]
pub struct Event {
    #[serde(rename(serialize = "id", deserialize = "id"))]
    pub prefix: Prefix,

    // TODO a backhash/digest of previous message?
    pub sn: u64,

    #[serde(flatten)]
    pub event_data: EventData,
}

impl EventSemantics for Event {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, &str> {
        // prefix must equal. sn must be incremented unless it is 0 (default state, should remain 0 after icp)
        if state.prefix != self.prefix
            || (self.sn != state.sn + 1 && !(self.sn == 0 && state.sn == 0))
        {
            return Err("dang");
        }

        Ok(IdentifierState {
            sn: self.sn,
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
  \"id\": \"AXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148\",
  \"sn\": 0,
  \"ilk\": \"icp\",
  \"sith\": 2,
  \"keys\":
  [
    \"AWoNZsa88VrTkep6HQt27fTh-4HA8tr54sHON1vWl6FE\",
    \"A8tr54sHON1vWVrTkep6H-4HAl6FEQt27fThWoNZsa88\",
    \"AVrTkep6HHA8tr54sHON1Qt27fThWoNZsa88-4vWl6FE\"
  ],
  \"next\": \"EWoNZsa88VrTkep6HQt27fTh-4HA8tr54sHON1vWl6FE\",
  \"toad\": 2,
  \"adds\":
  [
    \"AVrTkep6H-Qt27fThWoNZsa884HA8tr54sHON1vWl6FE\",
    \"AHON1vWl6FEQt27fThWoNZsa88VrTkep6H-4HA8tr54s\",
    \"AThWoNZsa88VrTkeQt27fp6H-4HA8tr54sHON1vWl6FE\"
  ],
  \"cuts\": []
}";

        let event: Event = serde_json::from_str(event_str)?;

        print!("\n{}\n", serde_json::to_string(&event)?);

        Ok(())
    }
}
