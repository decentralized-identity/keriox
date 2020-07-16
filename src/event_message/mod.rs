use crate::{
    derivation::sha3_512_digest,
    error::Error,
    event::Event,
    prefix::Prefix,
    state::{EventSemantics, IdentifierState, Verifiable},
    util::dfs_serializer::to_string,
};
use core::str::FromStr;
use serde::{Deserialize, Serialize};

/// Versioned Event Message
///
/// A VersionedEventMessage represents any signed message involved in any version of the KERI protocol
#[derive(Serialize, Deserialize)]
#[serde(tag = "vs")]
pub enum VersionedEventMessage {
    #[serde(rename = "KERI_0.1")]
    V0_0(EventMessage),
}

/// Event Message
///
/// An EventMessage represents any signed message involved in the KERI protocol
#[derive(Serialize, Deserialize)]
pub struct EventMessage {
    #[serde(flatten)]
    pub event: Event,

    #[serde(rename = "sigs")]
    pub sig_config: Vec<usize>,

    /// Appended Signatures
    ///
    /// TODO in the recommended JSON encoding, the signatures are appended to the json body.
    #[serde(skip)]
    pub signatures: Vec<Prefix>,
}

impl EventSemantics for EventMessage {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        self.event.apply_to(state)
    }
}

impl EventSemantics for VersionedEventMessage {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        match self {
            Self::V0_0(e) => e.apply_to(state),
        }
    }
}

impl Verifiable for VersionedEventMessage {
    fn verify_against(&self, state: &IdentifierState) -> Result<bool, Error> {
        // TODO better way of getting digest prefixes, also this always assumes SHA3-512 digests
        let serialized_data_extract =
            Prefix::SHA3_512(sha3_512_digest(to_string(self)?.as_bytes()));

        // extract relevant keys from state
        match self {
            Self::V0_0(e) => e
                .sig_config
                .iter()
                // get the signing keys indexed by event sig_config
                .map(|&index| &state.current.signers[index])
                // match them with the signatures
                .zip(&e.signatures)
                // check that each is valid
                .fold(Ok(true), |acc, (key, sig)| {
                    Ok(acc? && key.verify(&serialized_data_extract, sig)?)
                }),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct IcpWithKeys {
    icp: String,
    sk0: String,
    sk1: String,
}

pub fn get_icp() -> Result<IcpWithKeys, Error> {
    use crate::{
        event::{
            event_data::{inception::InceptionEvent, EventData},
            sections::{InceptionWitnessConfig, KeyConfig},
        },
        util::dfs_serializer,
    };
    use ursa::signatures::{ed25519::Ed25519Sha512, SignatureScheme};

    let ed = Ed25519Sha512::new();

    // get two ed25519 keypairs
    let (pub_key0, priv_key0) = ed
        .keypair(Option::None)
        .map_err(|e| Error::CryptoError(e))?;

    let (pub_key1, priv_key1) = ed
        .keypair(Option::None)
        .map_err(|e| Error::CryptoError(e))?;

    // initial signing key prefix
    let pref0 = Prefix::PubKeyEd25519(pub_key0);

    // initial control key hash prefix
    let pref1 = Prefix::SHA3_512(sha3_512_digest(&pub_key1.0));

    let icp = VersionedEventMessage::V0_0(EventMessage {
        event: Event {
            prefix: pref0.clone(),
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
        sig_config: vec![0],
        signatures: vec![],
    });

    let serialized = dfs_serializer::to_string(&icp)?;
    //
    // serialised extracted data, hashed and made into a prefix
    let sed = Prefix::SHA3_512(sha3_512_digest(serialized.as_bytes()));

    let str_event =
        serde_json::to_string(&icp).map_err(|e| Error::SerializationError(e.to_string()))?;

    let devent: VersionedEventMessage = serde_json::from_str(&str_event)
        .map_err(|e| Error::DeserializationError(core::fmt::Error))?;

    let sig = ed
        .sign(sed.to_string().as_bytes(), &priv_key0)
        .map_err(|e| Error::CryptoError(e))?;

    let sig_pref = Prefix::SigEd25519Sha512(sig);

    let signed_event = match devent {
        VersionedEventMessage::V0_0(ev) => VersionedEventMessage::V0_0(EventMessage {
            signatures: vec![sig_pref],
            ..ev
        }),
    };

    Ok(IcpWithKeys {
        icp: serialize_signed_message(signed_event),
        sk0: base64::encode_config(&priv_key0.0, base64::URL_SAFE),
        sk1: base64::encode_config(&priv_key1.0, base64::URL_SAFE),
    })
}

const SIG_DELIMITER: &str = "\n";

pub fn parse_signed_message(message: String) -> Result<VersionedEventMessage, Error> {
    let parts: Vec<&str> = message.split("\r\n\r\n").collect();
    let sigs: Vec<&str> = parts[0].split(SIG_DELIMITER).collect();

    Ok(VersionedEventMessage::V0_0(EventMessage {
        signatures: sigs
            .iter()
            .map(|sig| Prefix::from_str(sig))
            .collect::<Result<Vec<Prefix>, Error>>()?,
        ..serde_json::from_str(parts[0])
            .map_err(|_| Error::DeserializationError(core::fmt::Error))?
    }))
}

pub fn serialize_signed_message(message: VersionedEventMessage) -> String {
    [
        serde_json::to_string(&message).unwrap_or("HELL".to_string()),
        match message {
            VersionedEventMessage::V0_0(ev) => ev
                .signatures
                .iter()
                .map(|sig| ["\"".to_string(), sig.to_string(), "\"".to_string()].join(""))
                .collect::<Vec<String>>()
                .join(SIG_DELIMITER),
        },
    ]
    .join("\r\n\r\n")
}

pub fn validate_events(kel: &[VersionedEventMessage]) -> String {
    use crate::util::did_doc::DIDDocument;
    let sn = kel.iter().fold(IdentifierState::default(), |s, e| {
        s.verify_and_apply(e).unwrap()
    });
    let dd: DIDDocument = sn.into();
    serde_json::to_string(&dd).unwrap()
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
        let pref0 = Prefix::PubKeyEd25519(pub_key0);

        // initial control key hash prefix
        let pref1 = Prefix::SHA3_512(sha3_512_digest(&pub_key1.0));

        // create a simple inception event
        let icp = VersionedEventMessage::V0_0(EventMessage {
            event: Event {
                prefix: pref0.clone(),
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
            sig_config: vec![0],
            signatures: vec![],
        });

        // serialised extracted data, hashed and made into a prefix
        let sed = Prefix::SHA3_512(sha3_512_digest(
            dfs_serializer::to_string(&icp)
                .map_err(|_| Error::SerializationError("bad serialize".to_string()))?
                .as_bytes(),
        ));

        let str_event = serde_json::to_string(&icp)
            .map_err(|_| Error::SerializationError("bad serialize".to_string()))?;

        let devent: VersionedEventMessage = serde_json::from_str(&str_event)
            .map_err(|_| Error::DeserializationError(std::fmt::Error))?;

        // sign
        let sig = ed
            .sign(sed.to_string().as_bytes(), &priv_key0)
            .map_err(|e| Error::CryptoError(e))?;
        let sig_pref = Prefix::SigEd25519Sha512(sig);

        assert!(true, pref0.verify(&sed, &sig_pref)?);

        let signed_event = match devent {
            VersionedEventMessage::V0_0(ev) => VersionedEventMessage::V0_0(EventMessage {
                signatures: vec![sig_pref],
                ..ev
            }),
        };

        let s_ = IdentifierState::default();

        let s0 = s_.verify_and_apply(&signed_event)?;

        assert_eq!(s0.prefix, pref0);
        assert_eq!(s0.sn, 0);
        assert_eq!(s0.last, Prefix::default());
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
