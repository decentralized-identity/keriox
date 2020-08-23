use crate::{
    error::Error,
    event::Event,
    prefix::{AttachedSignaturePrefix, BasicPrefix, Prefix},
    state::{EventSemantics, IdentifierState, Verifiable},
    util::dfs_serializer::to_string,
};
use core::str::FromStr;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct EventMessage {
    #[serde(rename = "vs")]
    pub version: String,

    #[serde(flatten)]
    pub event: Event,

    /// Appended Signatures
    #[serde(skip)]
    pub signatures: Vec<AttachedSignaturePrefix>,
    // Additional Data for forwards compat
    // #[serde(flatten)]
    // pub extra: HashMap<String, Value>,
}

impl EventSemantics for EventMessage {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        self.event.apply_to(state)
    }
}

impl Verifiable for EventMessage {
    fn verify_against(&self, state: &IdentifierState) -> Result<bool, Error> {
        let serialized_data_extract = to_string(self)?;

        Ok(self.signatures.len() >= state.current.threshold
            && self
                .signatures
                .iter()
                .fold(Ok(true), |acc: Result<bool, Error>, sig| {
                    Ok(acc?
                        && state
                            .current
                            .signers
                            .get(sig.index as usize)
                            .ok_or(Error::SemanticError("Key not present in state".to_string()))
                            .and_then(|key: &BasicPrefix| {
                                key.verify(serialized_data_extract.as_bytes(), &sig.sig)
                            })?)
                })?)
    }
}

const SIG_DELIMITER: &str = "\n";

pub fn parse_signed_message_json(message: &str) -> Result<EventMessage, Error> {
    let parts: Vec<&str> = message.split("\r\n\r\n").collect();

    let sigs: Vec<AttachedSignaturePrefix> = parts[1]
        .split(SIG_DELIMITER)
        .map(|sig| AttachedSignaturePrefix::from_str(sig))
        .collect::<Result<Vec<AttachedSignaturePrefix>, Error>>()?;

    Ok(EventMessage {
        signatures: sigs,
        ..serde_json::from_str(parts[0]).map_err(|_| Error::DeserializationError)?
    })
}

pub fn serialize_signed_message_json(message: &EventMessage) -> String {
    [
        serde_json::to_string(message).unwrap_or("HELL".to_string()),
        message
            .signatures
            .iter()
            .map(|sig| sig.to_str())
            .collect::<Vec<String>>()
            .join(SIG_DELIMITER),
    ]
    .join("\r\n\r\n")
}

pub fn validate_events(kel: &[EventMessage]) -> Result<IdentifierState, Error> {
    kel.iter().fold(Ok(IdentifierState::default()), |s, e| {
        s?.verify_and_apply(e)
    })
}

#[cfg(test)]
mod tests {
    use super::super::util::dfs_serializer;
    use super::*;
    use crate::{
        derivation::sha3_512_digest,
        event::{
            event_data::{inception::InceptionEvent, EventData},
            sections::InceptionWitnessConfig,
            sections::KeyConfig,
        },
        prefix::{
            AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, SelfAddressingPrefix,
            SelfSigningPrefix,
        },
    };
    use serde_json;
    use ursa::signatures::{ed25519, SignatureScheme};

    #[test]
    fn create() -> Result<(), Error> {
        // hi Ed!
        let ed = ed25519::Ed25519Sha512::new();

        // get two ed25519 keypairs
        let (pub_key0, priv_key0) = ed
            .keypair(Option::None)
            .map_err(|e| Error::CryptoError(e))?;
        let (pub_key1, _priv_key1) = ed
            .keypair(Option::None)
            .map_err(|e| Error::CryptoError(e))?;

        // initial signing key prefix
        let pref0 = BasicPrefix::Ed25519(pub_key0);

        // initial control key hash prefix
        let pref1 = SelfAddressingPrefix::SHA3_512(sha3_512_digest(&pub_key1.0));

        // create a simple inception event
        let icp = EventMessage {
            version: "KERI_0_0".to_string(),
            event: Event {
                prefix: IdentifierPrefix::Basic(pref0.clone()),
                sn: 0,
                event_data: EventData::Icp(InceptionEvent {
                    key_config: KeyConfig {
                        threshold: 1,
                        public_keys: vec![pref0.clone()],
                        threshold_key_digest: pref1.clone(),
                    },
                    witness_config: InceptionWitnessConfig {
                        tally: 0,
                        initial_witnesses: vec![],
                    },
                }),
            },
            signatures: vec![],
        };

        // serialised extracted dataset
        let sed = dfs_serializer::to_string(&icp)
            .map_err(|_| Error::SerializationError("bad serialize".to_string()))?;

        let str_event = serde_json::to_string(&icp)
            .map_err(|_| Error::SerializationError("bad serialize".to_string()))?;

        let devent: EventMessage =
            serde_json::from_str(&str_event).map_err(|_| Error::DeserializationError)?;

        // sign
        let sig = ed
            .sign(sed.as_bytes(), &priv_key0)
            .map_err(|e| Error::CryptoError(e))?;
        let attached_sig = AttachedSignaturePrefix {
            index: 0,
            sig: SelfSigningPrefix::Ed25519Sha512(sig),
        };

        assert!(pref0.verify(sed.as_bytes(), &attached_sig.sig)?);

        let signed_event = EventMessage {
            signatures: vec![attached_sig],
            ..devent
        };

        let s_ = IdentifierState::default();

        let s0 = s_.verify_and_apply(&signed_event)?;

        assert_eq!(s0.prefix, IdentifierPrefix::Basic(pref0.clone()));
        assert_eq!(s0.sn, 0);
        assert_eq!(s0.last, SelfAddressingPrefix::default());
        assert_eq!(s0.current.signers.len(), 1);
        assert_eq!(s0.current.signers[0], pref0);
        assert_eq!(s0.current.threshold, 1);
        assert_eq!(s0.next, pref1);
        assert_eq!(s0.witnesses, vec![]);
        assert_eq!(s0.tally, 0);
        assert_eq!(s0.delegated_keys, vec![]);

        Ok(())
    }
}
