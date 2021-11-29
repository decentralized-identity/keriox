use std::{convert::TryFrom, sync::{Arc, Mutex}};

use crate::{database::sled::SledEventDatabase, derivation::basic::Basic, derivation::self_addressing::SelfAddressing, derivation::self_signing::SelfSigning, error::Error, event::sections::seal::{
        DigestSeal,
        Seal
    }, event::{
        event_data::EventData,
        Event,
        EventMessage,
        SerializationFormats
    }, event::{
        event_data::{
            Receipt,
            InteractionEvent,
        },
        sections::seal::EventSeal
    }, event_message::{signed_event_message::{SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt, Message}}, event_message::{
        event_msg_builder::{EventMsgBuilder, EventType},
    }, event_parsing::{SignedEventData, message::{signed_event_stream, signed_message}}, keys::PublicKey, prefix::AttachedSignaturePrefix, prefix::{
        BasicPrefix,
        IdentifierPrefix,
        SelfSigningPrefix
    }, processor::EventProcessor, signer::KeyManager, state::{
        EventSemantics,
        IdentifierState
    }};
#[cfg(feature = "wallet")]
use universal_wallet::prelude::{Content, UnlockedWallet};

#[cfg(feature = "query")]
use crate::query::SignedEnvelope;

#[cfg(test)]
mod test;
pub struct Keri<K: KeyManager + 'static> {
    prefix: IdentifierPrefix,
    key_manager: Arc<Mutex<K>>,
    processor: EventProcessor,
}

#[cfg(feature = "wallet")]
impl Keri<UnlockedWallet> {
    /// Instantiates KERI with freshly created and pre-populated wallet
    /// Wallet has ECDSA and X25519 key pairs
    /// Only available with crate `wallet` feature.
    ///
    pub fn new_with_fresh_wallet(
        db: Arc<SledEventDatabase>,
    ) -> Result<Keri<UnlockedWallet>, Error> {
        use crate::{
            prefix::Prefix,
            signer::wallet::{incept_keys, CURRENT},
        };
        // instantiate wallet with random ID instead of static for security reasons
        let mut wallet = UnlockedWallet::new(&generate_random_string());
        incept_keys(&mut wallet)?;
        let pk = match wallet.get_key(CURRENT).unwrap().content {
            Content::PublicKey(pk) => pk.public_key,
            Content::KeyPair(kp) => kp.public_key.public_key,
            Content::Entropy(_) => {
                return Err(Error::WalletError(universal_wallet::Error::KeyNotFound))
            }
        };
        let prefix =
            IdentifierPrefix::Basic(BasicPrefix::new(Basic::ECDSAsecp256k1, PublicKey::new(pk)));
        // setting wallet's ID to prefix of identity instead of random string
        wallet.id = prefix.to_str();
        Ok(Keri {
            prefix,
            key_manager: Arc::new(Mutex::new(wallet)),
            processor: EventProcessor::new(db),
        })
    }
}

impl<K: KeyManager> Keri<K> {
    // incept a state and keys
    pub fn new(db: Arc<SledEventDatabase>, key_manager: Arc<Mutex<K>>) -> Result<Keri<K>, Error> {
        Ok(Keri {
            prefix: IdentifierPrefix::default(),
            key_manager,
            processor: EventProcessor::new(db),
        })
    }

    /// Getter of the instance prefix
    ///
    pub fn prefix(&self) -> &IdentifierPrefix {
        &self.prefix
    }

    /// Getter of ref to owned `KeyManager` instance
    ///
    pub fn key_manager(&self) -> Arc<Mutex<K>> {
        self.key_manager.clone()
    }

    // Getter of the DB instance behind own processor
    ///
    pub fn db(&self) -> Arc<SledEventDatabase> {
        Arc::clone(&self.processor.db)
    }

    pub fn process(&self, id: &IdentifierPrefix, event: impl EventSemantics) -> Result<(), Error> {
        match self.processor.process_actual_event(id, event) {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(Error::SemanticError("Unknown identifier.".into())),
            Err(e) => Err(e),
        }
    }

    pub fn incept(&mut self) -> Result<SignedEventMessage, Error> {
        let km = self.key_manager.lock().map_err(|_| Error::MutexPoisoned)?;
        let icp = EventMsgBuilder::new(EventType::Inception)
            .with_prefix(&self.prefix)
            .with_keys(vec![Basic::Ed25519.derive(km.public_key())])
            .with_next_keys(vec![Basic::Ed25519.derive(km.next_public_key())])
            .build()?;

        let signed = icp.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            km.sign(&icp.serialize()?)?,
            0,
        )], None);

        self.processor
            .process(Message::Event(signed.clone()))?;

        self.prefix = icp.event.prefix;

        Ok(signed)
    }

    /// Incepts instance of KERI and includes EXTRA keys provided as parameter
    /// CURRENT Public verification key is extracted directly from KeyManager
    ///  - it should not be included into `extra_keys` set.
    /// # Parameters
    /// * `extra_keys` - iterator over tuples of `(keri::derivation::Basic, keri::keys::Key)`
    /// # Returns
    /// `Result<keri::event_message::SignedEventMessage, keri::error::Error>`
    ///  where `SignedEventMessage` is ICP event including all provided keys + directly fetched
    ///  verification key, signed with it's private key via KeyManager and serialized.
    ///
    pub fn incept_with_extra_keys(&mut self, extra_keys: impl IntoIterator<Item = (Basic, PublicKey)>) 
        -> Result<SignedEventMessage, Error> {
            let mut keys: Vec<BasicPrefix> = extra_keys
                .into_iter()
                .map(|(key_type, key)| key_type.derive(key)).collect();
            // Signing key must be first
            let km = self.key_manager.lock().map_err(|_| Error::MutexPoisoned)?;
            keys.insert(0, Basic::Ed25519.derive(km.public_key()));
            let icp = EventMsgBuilder::new(EventType::Inception)
                .with_prefix(&self.prefix)
                .with_keys(keys)
                .with_next_keys(vec!(Basic::Ed25519.derive(km.next_public_key())))
                .build()?;

            let signed = icp.sign(vec!(
                AttachedSignaturePrefix::new(
                    SelfSigning::Ed25519Sha512,
                    km.sign(&icp.serialize()?)?,
                    0
                )
            ), None);
            self.processor.process(Message::Event(signed.clone()))?;
            self.prefix = icp.event.prefix;

            Ok(signed)
    }

    /// Interacts with peer identifier via generation of a `Seal`
    /// Seal gets added to our KEL db and returned back as `SignedEventMessage`
    ///
    pub fn interact(&self, peer: IdentifierPrefix) -> Result<SignedEventMessage, Error> {
        let next_sn = match self.processor.db.get_kel_finalized_events(&self.prefix) {
            Some(mut events) => match events.next_back() {
                Some(db_event) => db_event.signed_event_message.event_message.event.sn + 1,
                None => return Err(Error::InvalidIdentifierStat),
            },
            None => return Err(Error::InvalidIdentifierStat),
        };
        let (pref, seal) = match peer {
            IdentifierPrefix::SelfAddressing(pref) => {
                (pref.clone(), Seal::Digest(DigestSeal { dig: pref }))
            }
            _ => {
                return Err(Error::SemanticError(
                    "Can interact with SelfAdressing prefixes only".into(),
                ))
            }
        };
        let event = EventMessage::new(
            Event::new(
                self.prefix.clone(),
                next_sn,
                EventData::Ixn(InteractionEvent::new(pref, vec![seal])),
            ),
            SerializationFormats::JSON,
        )?;
        let serialized = event.serialize()?;
        let signature = self
            .key_manager
            .lock()
            .map_err(|_| Error::MutexPoisoned)?
            .sign(&serialized)?;
        let asp = AttachedSignaturePrefix::new(
            SelfSigning::ECDSAsecp256k1Sha256,
            signature,
            0, // TODO: what is this?
        );
        let signed = SignedEventMessage::new(&event, vec!(asp), None);
        self.processor.db.add_kel_finalized_event(signed.clone(), &self.prefix)?;
        Ok(signed)
    }

    pub fn rotate(&mut self) -> Result<SignedEventMessage, Error> {
        self.key_manager
            .lock()
            .map_err(|_| Error::MutexPoisoned)?
            .rotate()?;
        let rot = self.make_rotation()?;
        let rot = rot.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            self.key_manager
                    .lock()
                    .map_err(|_| Error::MutexPoisoned)?
                    .sign(&rot.serialize()?)?,
            0,
        )], None);

        self.processor
            .process(Message::Event(rot.clone()))?;

        Ok(rot)
    }

    fn make_rotation(&self) -> Result<EventMessage<Event>, Error> {
        let state = self
            .processor
            .compute_state(&self.prefix)?
            .ok_or(Error::SemanticError("There is no state".into()))?;
        match self.key_manager.lock() {
            Ok(kv) => EventMsgBuilder::new(EventType::Rotation)
                .with_prefix(&self.prefix)
                .with_sn(state.sn + 1)
                .with_previous_event(&SelfAddressing::Blake3_256.derive(&state.last))
                .with_keys(vec![Basic::Ed25519.derive(kv.public_key())])
                .with_next_keys(vec![Basic::Ed25519.derive(kv.next_public_key())])
                .build(),
            Err(_) => Err(Error::MutexPoisoned),
        }
    }

    pub fn make_ixn(&mut self, payload: Option<&str>) -> Result<SignedEventMessage, Error> {
        let seal_list = match payload {
            Some(payload) => {
                vec![Seal::Digest(DigestSeal {
                    dig: SelfAddressing::Blake3_256.derive(payload.as_bytes()),
                })]
            }
            None => vec![],
        };
        let state = self
            .processor
            .compute_state(&self.prefix)?
            .ok_or(Error::SemanticError("There is no state".into()))?;

        let ev = EventMsgBuilder::new(EventType::Interaction)
            .with_prefix(&self.prefix)
            .with_sn(state.sn + 1)
            .with_previous_event(&SelfAddressing::Blake3_256.derive(&state.last))
            .with_seal(seal_list)
            .build()?;

        let ixn = ev.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            self.key_manager
                    .lock()
                    .map_err(|_| Error::MutexPoisoned)?
                    .sign(&ev.serialize()?)?,
            0,
        )], None);

        self.processor
            .process(Message::Event(ixn.clone()))?;

        Ok(ixn)
    }

    /// Process and respond to single event
    ///
    pub fn respond_single(&self, msg: &[u8]) -> Result<(IdentifierPrefix, Vec<u8>), Error> {
        let parsed = signed_message(msg).map_err(|e| Error::DeserializeError(e.to_string()))?;
        match Message::try_from(parsed.1) {
            Err(e) => Err(Error::DeserializeError(e.to_string())),
            Ok(event) => {
                match self.processor.process(event)? {
                    None => Err(Error::InvalidIdentifierStat),
                    Some(state) => Ok((state.prefix.clone(), serde_json::to_vec(&state)?)),
                }
            }
        }
    }

    pub fn respond(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let events = signed_event_stream(msg)
            .map_err(|e| Error::DeserializeError(e.to_string()))?
            .1;
        let (processed_ok, _processed_failed): (Vec<_>, Vec<_>) = events
            .into_iter()
            .map(|event| {
                self.processor
                    .process(Message::try_from(event.clone()).unwrap())
                    .and_then(|_| Message::try_from(event))
            })
            .partition(Result::is_ok);
        let response: Vec<u8> = processed_ok
            .into_iter()
            .map(Result::unwrap)
            .map(|des_event| -> Result<Vec<u8>, Error> {
                match des_event {
                    Message::Event(ev) => {
                        let mut buf = vec![];
                        if let EventData::Icp(_) = ev.event_message.event.event_data {
                            if !self.processor.has_receipt(
                                &self.prefix,
                                0,
                                &ev.event_message.event.prefix,
                            )? {
                                buf.append(
                                    &mut self
                                        .processor
                                        .get_kerl(&self.prefix)?
                                        .ok_or(Error::SemanticError("KEL is empty".into()))?,
                                )
                            }
                        }
                        let rcp: SignedEventData = self.make_rct(ev.event_message.clone())?.into();
                        buf.append(&mut rcp.to_cesr().unwrap());
                        Ok(buf)
                    }
                    // TODO: this should process properly
                    _ => Ok(vec![]),
                }
            })
            .filter_map(|x| x.ok())
            .flatten()
            .collect();
        Ok(response)
    }

    pub fn make_rct(&self, event: EventMessage<Event>) -> Result<SignedTransferableReceipt, Error> {
        let ser = event.serialize()?;
        let signature = self
            .key_manager
            .lock()
            .map_err(|_| Error::MutexPoisoned)?
            .sign(&ser)?;
        let validator_event_seal = self
            .processor
            .get_last_establishment_event_seal(&self.prefix)?
            .ok_or(Error::SemanticError("No establishment event seal".into()))?;
        let rcp = Event {
            prefix: event.event.prefix,
            sn: event.event.sn,
            event_data: EventData::Rct(Receipt {
                receipted_event_digest: SelfAddressing::Blake3_256.derive(&ser),
            }),
        }
        .to_message(SerializationFormats::JSON)?;

        let signatures = vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )];
        let signed_rcp = SignedTransferableReceipt::new(&rcp, validator_event_seal, signatures);

        self.processor
            .process(Message::TransferableRct(signed_rcp.clone()))?;

        Ok(signed_rcp)
    }

    /// Create `SignedNontransferableReceipt` for given `EventMessage`
    /// This will actually process and generate receipt if we are added as witness
    /// Generated receipt will be stored into `ntp` DB table under sender's identifier
    /// Ignore and return `Error::SemanticError` with description why no receipt returned
    ///
    /// # Parameters
    /// * `message` - `EventMessage` we are to process
    ///
    pub fn make_ntr(&self, message: EventMessage<Event>) -> Result<SignedNontransferableReceipt, Error> {
        let our_bp = match &self.prefix {
            IdentifierPrefix::Basic(prefix) => prefix,
            _ => {
                return Err(Error::SemanticError(
                    "we are not a witness - our prefix is not Basic".into(),
                ))
            }
        };
        match &message.event.event_data {
            // ICP requires check if we are in initial witnesses only
            EventData::Icp(evt) => {
                if !evt.witness_config.initial_witnesses.contains(&our_bp) {
                    return Err(Error::SemanticError("we are not in a witness list.".into()));
                }
                self.generate_ntr(message)
            }
            EventData::Rot(evt) => {
                if !evt.witness_config.prune.contains(&our_bp) {
                    if evt.witness_config.graft.contains(&our_bp) {
                        // FIXME: logic for already witnessed identifier required
                        self.generate_ntr(message)
                    } else {
                        Err(Error::SemanticError(
                            "event does not change our status as a witness".into(),
                        ))
                    }
                } else if evt.witness_config.prune.contains(&our_bp) {
                    self.processor
                        .db
                        .remove_receipts_nt(&message.event.prefix)?;
                    Err(Error::SemanticError(
                        "we were removed. no receipt to generate".into(),
                    ))
                } else {
                    Err(Error::SemanticError(
                        "event without witness modifications".into(),
                    ))
                }
            }
            _ => Err(Error::SemanticError(
                "event without witness modifications".into(),
            )),
        }
    }

    pub fn get_state(&self) -> Result<Option<IdentifierState>, Error> {
        self.processor.compute_state(&self.prefix)
    }

    pub fn get_kerl(&self) -> Result<Option<Vec<u8>>, Error> {
        self.processor.get_kerl(&self.prefix)
    }

    pub fn get_state_for_prefix(
        &self,
        prefix: &IdentifierPrefix,
    ) -> Result<Option<IdentifierState>, Error> {
        self.processor.compute_state(prefix)
    }

    pub fn get_state_for_seal(&self, seal: &EventSeal) -> Result<Option<IdentifierState>, Error> {
        self.processor.compute_state_at_sn(&seal.prefix, seal.sn)
    }

    fn generate_ntr(&self, message: EventMessage<Event>) -> Result<SignedNontransferableReceipt, Error> {
        let signature;
        let bp;
        match self.key_manager.lock() {
            Ok(km) => {
                signature = km.sign(&message.serialize()?)?;
                bp = BasicPrefix::new(Basic::Ed25519, km.public_key());
            }
            Err(_) => return Err(Error::MutexPoisoned),
        }
        let ssp = SelfSigningPrefix::new(SelfSigning::Ed25519Sha512, signature);
        let rcp = Event {
            prefix: message.event.prefix.clone(),
            sn: message.event.sn,
            event_data: EventData::Rct(Receipt {
                receipted_event_digest: SelfAddressing::Blake3_256.derive(&message.serialize()?),
            }),
        }
        .to_message(SerializationFormats::JSON)?;
        let ntr = SignedNontransferableReceipt::new(&rcp, vec![(bp, ssp)]);
        self.processor
            .db
            .add_receipt_nt(ntr.clone(), &message.event.prefix)?;
        Ok(ntr)
    }

    #[cfg(feature = "query")]
    fn process_query(&self, qr: SignedEnvelope) -> Result<Vec<u8>, Error> {
        let signatures = qr.signatures;
            // check signatures
            let kc = self.get_state_for_prefix(&qr.signer)?
                .ok_or(Error::SemanticError("No identifier in db".into()))?
                .current;
            if kc.verify(&qr.envelope.serialize().unwrap(), &signatures)? {
                // TODO check timestamps
                // unpack and check database for given id
                match qr.envelope.event.message {
                    crate::query::MessageType::Qry(qr) => {
                        Ok(self.processor.get_kerl(&qr.data.i)?.ok_or(Error::SemanticError("No identifier in db".into()))?)
                    },
                    crate::query::MessageType::Rpy(_) => todo!(),
                }
            } else {
                Err(Error::SignatureVerificationError)
            }
        }
}

// Non re-allocating random `String` generator with output length of 10 char string
#[cfg(feature = "wallet")]
fn generate_random_string() -> String {
    use rand::Rng;
    const ALL: [char; 61] = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
        'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
        'k', 'l', 'm', 'n', 'o', 'p', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '9', '8',
        '7', '6', '5', '4', '3', '2', '1',
    ];
    let mut ret = String::default();
    for _ in 0..10 {
        let n = rand::thread_rng().gen_range(0, ALL.len());
        ret.push(ALL[n]);
    }
    ret
}

#[cfg(test)]
#[cfg(feature = "wallet")]
mod keri_wallet {
    #[test]
    fn random_string_test() {
        let rst = super::generate_random_string();
        assert!(!rst.is_empty());
        assert!(rst != super::generate_random_string());
    }
}
