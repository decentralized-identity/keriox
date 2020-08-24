use crate::{
    error::Error,
    event::Event,
    prefix::{attached_signature::get_sig_count, AttachedSignaturePrefix, BasicPrefix, Prefix},
    state::{EventSemantics, IdentifierState, Verifiable},
    util::dfs_serializer,
};
use core::str::FromStr;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EventMessage {
    /// Version and Size string
    ///
    /// TODO should be broken up into better types
    #[serde(rename = "vs")]
    version: String,

    #[serde(flatten)]
    pub event: Event,

    /// Appended Signatures
    #[serde(skip)]
    pub signatures: Vec<AttachedSignaturePrefix>,
    // Additional Data for forwards compat
    // #[serde(flatten)]
    // pub extra: HashMap<String, Value>,
}

impl EventMessage {
    pub fn new(event: &Event, sigs: Vec<AttachedSignaturePrefix>) -> Result<Self, Error> {
        Ok(Self {
            version: format!("KERI10JSON{:06x}_", event.get_serialized_size()?),
            event: event.clone(),
            signatures: sigs,
        })
    }

    pub fn get_size(event: &Event) -> Result<usize, Error> {
        Ok(serde_json::to_string(&Self {
            version: "KERI10JSON000000_".to_string(),
            event: event.clone(),
            signatures: vec![],
        })
        .map_err(|_| Error::DeserializationError)?
        .len())
    }

    /// Extract Serialized Data Set
    ///
    /// returns the serialized extracted data set (for signing/verification) for this event message
    pub fn extract_serialized_data_set(&self) -> Result<String, Error> {
        dfs_serializer::to_string(self)
    }
}

impl EventSemantics for EventMessage {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        self.event.apply_to(state)
    }
}

impl Verifiable for EventMessage {
    fn verify_against(&self, state: &IdentifierState) -> Result<bool, Error> {
        let serialized_data_extract = self.extract_serialized_data_set()?;

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

const JSON_SIG_DELIMITER: &str = "\n";

pub fn parse_signed_message_json(message: &str) -> Result<EventMessage, Error> {
    let parts: Vec<&str> = message.split(JSON_SIG_DELIMITER).collect();

    let sigs: Vec<AttachedSignaturePrefix> = parts[1..]
        .iter()
        .map(|sig| AttachedSignaturePrefix::from_str(sig))
        .collect::<Result<Vec<AttachedSignaturePrefix>, Error>>()?;

    Ok(EventMessage {
        signatures: sigs,
        ..serde_json::from_str(parts[0])?
    })
}

pub fn serialize_signed_message_json(message: &EventMessage) -> Result<String, Error> {
    Ok([
        serde_json::to_string(message)?,
        get_sig_count(message.signatures.len().try_into().unwrap()),
        message
            .signatures
            .iter()
            .map(|sig| sig.to_str())
            .collect::<Vec<String>>()
            .join(JSON_SIG_DELIMITER),
    ]
    .join(JSON_SIG_DELIMITER))
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
        derivation::{blake2b_256_digest, sha3_512_digest},
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
    use ursa::{
        kex::{x25519, KeyExchangeScheme},
        signatures::{ed25519, SignatureScheme},
    };

    #[test]
    fn basic_create() -> Result<(), Error> {
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
        let icp = Event {
            prefix: IdentifierPrefix::Basic(pref0.clone()),
            sn: 0,
            event_data: EventData::Icp(InceptionEvent {
                key_config: KeyConfig {
                    threshold: 1,
                    public_keys: vec![pref0.clone()],
                    threshold_key_digest: pref1.clone(),
                },
                witness_config: InceptionWitnessConfig::default(),
                inception_configuration: vec![],
            }),
        };

        // serialised extracted dataset
        let sed = icp.extract_serialized_data_set()?;

        // sign
        let sig = ed
            .sign(sed.as_bytes(), &priv_key0)
            .map_err(|e| Error::CryptoError(e))?;
        let attached_sig = AttachedSignaturePrefix {
            index: 0,
            sig: SelfSigningPrefix::Ed25519Sha512(sig),
        };

        assert!(pref0.verify(sed.as_bytes(), &attached_sig.sig)?);

        let signed_event = icp.sign(vec![attached_sig])?;

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

    #[test]
    fn self_addressing_create() -> Result<(), Error> {
        // hi Ed!
        let ed = ed25519::Ed25519Sha512::new();

        let (sig_key_0, sig_priv_0) = ed
            .keypair(Option::None)
            .map_err(|e| Error::CryptoError(e))?;
        let (sig_key_1, sig_priv_1) = ed
            .keypair(Option::None)
            .map_err(|e| Error::CryptoError(e))?;

        // hi X!
        let x = x25519::X25519Sha256::new();

        // get two X25519 keypairs
        let (enc_key_0, enc_priv_0) = x.keypair(Option::None).map_err(|e| Error::CryptoError(e))?;
        let (enc_key_1, enc_priv_1) = x.keypair(Option::None).map_err(|e| Error::CryptoError(e))?;

        // initial key set
        let sig_pref_0 = BasicPrefix::Ed25519(sig_key_0);
        let enc_pref_0 = BasicPrefix::X25519(enc_key_0);

        // next key set
        let sig_pref_1 = BasicPrefix::Ed25519(sig_key_1);
        let enc_pref_1 = BasicPrefix::X25519(enc_key_1);

        // next key set pre-commitment
        let nexter_pref = SelfAddressingPrefix::Blake2B256(blake2b_256_digest(
            [sig_pref_1.to_str(), enc_pref_1.to_str()]
                .join("")
                .as_bytes(),
        ));

        let icp_data = Event {
            prefix: IdentifierPrefix::default(),
            sn: 0,
            event_data: EventData::Icp(InceptionEvent {
                key_config: KeyConfig {
                    threshold: 1,
                    public_keys: vec![sig_pref_0.clone(), enc_pref_0.clone()],
                    threshold_key_digest: nexter_pref.clone(),
                },
                witness_config: InceptionWitnessConfig::default(),
                inception_configuration: vec![],
            }),
        };

        let pref = IdentifierPrefix::SelfAddressing(SelfAddressingPrefix::Blake2B256(
            blake2b_256_digest(icp_data.extract_serialized_data_set()?.as_bytes()),
        ));

        let icp_event = Event {
            prefix: pref.clone(),
            ..icp_data
        };

        // serialised extracted dataset
        let sed = icp_event.extract_serialized_data_set()?;

        // sign
        let sig = ed
            .sign(sed.as_bytes(), &sig_priv_0)
            .map_err(|e| Error::CryptoError(e))?;
        let attached_sig = AttachedSignaturePrefix {
            index: 0,
            sig: SelfSigningPrefix::Ed25519Sha512(sig),
        };

        assert!(sig_pref_0.verify(sed.as_bytes(), &attached_sig.sig)?);

        let signed_event = icp_event.sign(vec![attached_sig])?;

        let s_ = IdentifierState::default();

        let s0 = s_.verify_and_apply(&signed_event)?;

        assert_eq!(s0.prefix, pref);
        assert_eq!(s0.sn, 0);
        assert_eq!(s0.last, SelfAddressingPrefix::default());
        assert_eq!(s0.current.signers.len(), 2);
        assert_eq!(s0.current.signers[0], sig_pref_0);
        assert_eq!(s0.current.signers[1], enc_pref_0);
        assert_eq!(s0.current.threshold, 1);
        assert_eq!(s0.next, nexter_pref);
        assert_eq!(s0.witnesses, vec![]);
        assert_eq!(s0.tally, 0);
        assert_eq!(s0.delegated_keys, vec![]);

        Ok(())
    }
}
