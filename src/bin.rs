use clap::{App, Arg};
use keri::{
    derivation::{basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning},
    error::Error,
    event::{
        event_data::{
            inception::InceptionEvent, interaction::InteractionEvent, receipt::ReceiptTransferable,
            rotation::RotationEvent, EventData,
        },
        sections::{seal::EventSeal, InceptionWitnessConfig, KeyConfig, WitnessConfig},
        Event,
    },
    event_message::{
        parse::signed_message, serialization_info::SerializationFormats, EventMessage,
        SignedEventMessage,
    },
    prefix::{AttachedSignaturePrefix, IdentifierPrefix, Prefix, SelfAddressingPrefix},
    state::IdentifierState,
    util::dfs_serializer,
};
use std::collections::HashMap;
use ursa::{
    keys::{PrivateKey, PublicKey},
    signatures::{ed25519, SignatureScheme},
};

struct LogState {
    pub log: Vec<SignedEventMessage>,
    pub sigs_map: HashMap<u64, Vec<SignedEventMessage>>,
    pub state: IdentifierState,
    pub keypair: (PublicKey, PrivateKey),
    pub next_keypair: (PublicKey, PrivateKey),
}
impl LogState {
    // incept a state and keys
    fn new() -> Result<LogState, Error> {
        let ed = ed25519::Ed25519Sha512::new();
        let keypair = ed
            .keypair(Option::None)
            .map_err(|e| Error::CryptoError(e))?;
        let next_keypair = ed
            .keypair(Option::None)
            .map_err(|e| Error::CryptoError(e))?;

        let icp_data = InceptionEvent {
            key_config: KeyConfig {
                threshold: 1,
                public_keys: vec![Basic::Ed25519.derive(keypair.0.clone())],
                threshold_key_digest: SelfAddressing::Blake3_256.derive(
                    Basic::Ed25519
                        .derive(next_keypair.0.clone())
                        .to_str()
                        .as_bytes(),
                ),
            },
            witness_config: InceptionWitnessConfig::default(),
            inception_configuration: vec![],
        };

        let icp_data_message = EventMessage::get_inception_data(
            &icp_data,
            SelfAddressing::Blake3_256,
            &SerializationFormats::JSON,
        );

        let pref = IdentifierPrefix::SelfAddressing(
            SelfAddressing::Blake3_256.derive(&dfs_serializer::to_vec(&icp_data_message)?),
        );

        let icp_m = Event {
            prefix: pref.clone(),
            sn: 0,
            event_data: EventData::Icp(icp_data),
        }
        .to_message(&SerializationFormats::JSON)?;

        let sigged = icp_m.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            ed.sign(&icp_m.serialize()?, &keypair.1)
                .map_err(|e| Error::CryptoError(e))?,
            0,
        )]);

        let s0 = IdentifierState::default().verify_and_apply(&sigged)?;

        Ok(LogState {
            log: vec![sigged],
            sigs_map: HashMap::new(),
            state: s0,
            keypair,
            next_keypair,
        })
    }

    // take a receipt made by validator, verify it and add to sigs_map
    fn add_sig(
        &mut self,
        validator: IdentifierState,
        sigs: SignedEventMessage,
    ) -> Result<(), Error> {
        match sigs.event_message.event.event_data.clone() {
            EventData::Vrc(rct) => {
                let event = self
                    .log
                    .get(sigs.event_message.event.sn as usize)
                    .ok_or(Error::SemanticError("incorrect receipt sn".into()))?;

                // This logic can in future be moved to the correct place in the Kever equivalent here
                // receipt pref is the ID who made the event being receipted
                if sigs.event_message.event.prefix == self.state.prefix
                            // dig is the digest of the event being receipted
                            && rct.receipted_event_digest
                                == rct
                                    .receipted_event_digest
                                    .derivation
                                    .derive(&event.event_message.serialize()?)
                            // seal pref is the pref of the validator
                            && rct.validator_location_seal.prefix == validator.prefix
                            // seal dig is the digest of the last establishment event for the validator
                            && rct.validator_location_seal.event_digest
                                == rct
                                    .validator_location_seal
                                    .event_digest
                                    .derivation
                                    .derive(&validator.last)
                {
                    validator.verify(&event.event_message.sign(sigs.signatures.clone()))?;
                    self.sigs_map
                        .entry(sigs.event_message.event.sn)
                        .or_insert_with(|| vec![])
                        .push(sigs);
                    Ok(())
                } else {
                    Err(Error::SemanticError("incorrect receipt binding".into()))
                }
            }
            _ => Err(Error::SemanticError("not a receipt".into())),
        }
    }

    fn make_rct(&self, event: EventMessage) -> Result<SignedEventMessage, Error> {
        let ser = event.serialize()?;
        Ok(Event {
            prefix: event.event.prefix,
            sn: event.event.sn,
            event_data: EventData::Vrc(ReceiptTransferable {
                receipted_event_digest: SelfAddressing::Blake3_256.derive(&ser),
                validator_location_seal: EventSeal {
                    prefix: self.state.prefix.clone(),
                    event_digest: SelfAddressing::Blake3_256.derive(&self.state.last),
                },
            }),
        }
        .to_message(&SerializationFormats::JSON)?
        .sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            ed25519::Ed25519Sha512::new()
                .sign(&ser, &self.keypair.1)
                .map_err(|e| Error::CryptoError(e))?,
            0,
        )]))
    }

    fn rotate(&mut self) -> Result<SignedEventMessage, Error> {
        let ed = ed25519::Ed25519Sha512::new();
        let keypair = ed
            .keypair(Option::None)
            .map_err(|e| Error::CryptoError(e))?;
        let next_keypair = ed
            .keypair(Option::None)
            .map_err(|e| Error::CryptoError(e))?;

        let ev = Event {
            prefix: self.state.prefix.clone(),
            sn: self.state.sn + 1,
            event_data: EventData::Rot(RotationEvent {
                previous_event_hash: SelfAddressing::Blake3_256.derive(&self.state.last),
                key_config: KeyConfig {
                    threshold: 1,
                    public_keys: vec![Basic::Ed25519.derive(keypair.0.clone())],
                    threshold_key_digest: SelfAddressing::Blake3_256.derive(
                        Basic::Ed25519
                            .derive(next_keypair.0.clone())
                            .to_str()
                            .as_bytes(),
                    ),
                },
                witness_config: WitnessConfig::default(),
                data: vec![],
            }),
        }
        .to_message(&SerializationFormats::JSON)?;

        let rot = ev.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            ed25519::Ed25519Sha512::new()
                .sign(&ev.serialize()?, &self.keypair.1)
                .map_err(|e| Error::CryptoError(e))?,
            0,
        )]);

        self.state = self.state.clone().verify_and_apply(&rot)?;

        self.keypair = keypair;
        self.next_keypair = next_keypair;

        Ok(rot)
    }
}

fn main() {}
