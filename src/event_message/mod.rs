use crate::{
    error::Error,
    event::Event,
    prefix::{attached_signature::get_sig_count, AttachedSignaturePrefix, BasicPrefix, Prefix},
    state::{EventSemantics, IdentifierState, Verifiable},
    util::dfs_serializer,
};
pub mod serialization_info;
use serde::{Deserialize, Serialize};
use serialization_info::*;
pub mod parse;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EventMessage {
    /// Version and Size string
    ///
    /// TODO should be broken up into better types
    #[serde(rename = "vs")]
    serialization_info: SerializationInfo,

    #[serde(flatten)]
    pub event: Event,
    // Additional Data for forwards compat
    // #[serde(flatten)]
    // pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone)]
pub struct SignedEventMessage {
    pub event_message: EventMessage,
    pub signatures: Vec<AttachedSignaturePrefix>,
}

impl EventMessage {
    pub fn new(event: &Event, format: &SerializationFormats) -> Result<Self, Error> {
        Ok(Self {
            serialization_info: SerializationInfo {
                major_version: 1,
                minor_version: 0,
                size: Self::get_size(event, format)? as u16,
                kind: *format,
            },
            event: event.clone(),
        })
    }

    fn get_size(event: &Event, format: &SerializationFormats) -> Result<usize, Error> {
        Ok(Self {
            serialization_info: SerializationInfo::new(format, 0),
            event: event.clone(),
        }
        .serialize()
        .map_err(|_| Error::DeserializationError)?
        .len())
    }

    pub fn serialization(&self) -> SerializationFormats {
        self.serialization_info.kind
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        self.serialization().encode(self)
    }

    /// Extract Serialized Data Set
    ///
    /// returns the serialized extracted data set (for signing/verification) for this event message
    /// NOTE: this method, for deserialized events, will be UNABLE to preserve ordering
    pub fn extract_serialized_data_set(&self) -> Result<String, Error> {
        dfs_serializer::to_string(self)
    }

    pub fn sign(&self, sigs: Vec<AttachedSignaturePrefix>) -> SignedEventMessage {
        SignedEventMessage::new(self, sigs)
    }
}

impl SignedEventMessage {
    pub fn new(message: &EventMessage, sigs: Vec<AttachedSignaturePrefix>) -> Self {
        Self {
            event_message: message.clone(),
            signatures: sigs,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        Ok([
            self.event_message.serialize()?,
            get_sig_count(self.signatures.len() as u16)
                .as_bytes()
                .to_vec(),
            self.signatures
                .iter()
                .map(|sig| sig.to_str().as_bytes().to_vec())
                .fold(vec![], |acc, next| [acc, next].concat()),
        ]
        .concat())
    }
}

impl EventSemantics for EventMessage {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        self.event.apply_to(state)
    }
}

impl EventSemantics for SignedEventMessage {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        self.event_message.apply_to(state)
    }
}

impl Verifiable for SignedEventMessage {
    fn verify_against(&self, state: &IdentifierState) -> Result<bool, Error> {
        let serialized_data_extract = self.event_message.extract_serialized_data_set()?;

        Ok(self.signatures.len() as u64 >= state.current.threshold
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

pub fn validate_events(kel: &[SignedEventMessage]) -> Result<IdentifierState, Error> {
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

        let icp_m = icp.to_message(&SerializationFormats::JSON)?;

        // serialised extracted dataset
        let sed = icp_m.extract_serialized_data_set()?;

        // sign
        let sig = ed
            .sign(sed.as_bytes(), &priv_key0)
            .map_err(|e| Error::CryptoError(e))?;
        let attached_sig = AttachedSignaturePrefix {
            index: 0,
            sig: SelfSigningPrefix::Ed25519Sha512(sig),
        };

        assert!(pref0.verify(sed.as_bytes(), &attached_sig.sig)?);

        let signed_event = icp_m.sign(vec![attached_sig]);

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

        let icp_data_message = icp_data.to_message(&SerializationFormats::JSON)?;

        let pref = IdentifierPrefix::SelfAddressing(SelfAddressingPrefix::Blake2B256(
            blake2b_256_digest(icp_data_message.extract_serialized_data_set()?.as_bytes()),
        ));

        let icp_m = Event {
            prefix: pref.clone(),
            ..icp_data
        }
        .to_message(&SerializationFormats::JSON)?;

        // serialised extracted dataset
        let sed = icp_m.extract_serialized_data_set()?;

        // sign
        let sig = ed
            .sign(sed.as_bytes(), &sig_priv_0)
            .map_err(|e| Error::CryptoError(e))?;
        let attached_sig = AttachedSignaturePrefix {
            index: 0,
            sig: SelfSigningPrefix::Ed25519Sha512(sig),
        };

        assert!(sig_pref_0.verify(sed.as_bytes(), &attached_sig.sig)?);

        let signed_event = icp_m.sign(vec![attached_sig]);

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
