use std::{
    convert::TryFrom,
    sync::{Arc, Mutex},
};

use crate::{
    database::sled::SledEventDatabase,
    derivation::basic::Basic,
    derivation::self_addressing::SelfAddressing,
    derivation::self_signing::SelfSigning,
    error::Error,
    event::sections::seal::{DigestSeal, Seal},
    event::{event_data::EventData, receipt::Receipt, Event, EventMessage, SerializationFormats},
    event::{event_data::InteractionEvent, sections::seal::EventSeal},
    event_message::event_msg_builder::EventMsgBuilder,
    event_message::{
        key_event_message::KeyEvent,
        signed_event_message::{
            Message, SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt,
        },
        EventTypeTag,
    },
    event_parsing::{
        message::{signed_event_stream, signed_message},
        SignedEventData,
    },
    keys::PublicKey,
    prefix::AttachedSignaturePrefix,
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    processor::EventProcessor,
    signer::KeyManager,
    state::{EventSemantics, IdentifierState},
};
#[cfg(feature = "wallet")]
use universal_wallet::prelude::{Content, UnlockedWallet};

#[cfg(test)]
mod test;
#[cfg(feature = "query")]
pub mod witness;
pub struct Keri<K: KeyManager + 'static> {
    prefix: IdentifierPrefix,
    key_manager: K,
    processor: EventProcessor,
}

#[cfg(feature = "wallet")]
impl Keri<Arc<Mutex<UnlockedWallet>>> {
    /// Instantiates KERI with freshly created and pre-populated wallet
    /// Wallet has ECDSA and X25519 key pairs
    /// Only available with crate `wallet` feature.
    ///
    pub fn new_with_fresh_wallet(
        db: Arc<SledEventDatabase>,
    ) -> Result<Keri<Arc<Mutex<UnlockedWallet>>>, Error> {
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

impl Keri<Arc<Mutex<UnlockedWallet>>> {
    // incept a state and keys
    pub fn new(
        db: Arc<SledEventDatabase>,
        key_manager: Arc<Mutex<UnlockedWallet>>,
    ) -> Result<Keri<Arc<Mutex<UnlockedWallet>>>, Error> {
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
    pub fn key_manager(&self) -> Arc<Mutex<UnlockedWallet>> {
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

    pub fn incept(
        &mut self,
        initial_witness: Option<Vec<BasicPrefix>>,
    ) -> Result<SignedEventMessage, Error> {
        let icp = EventMsgBuilder::new(EventTypeTag::Icp)
            .with_prefix(&self.prefix)
            .with_keys(vec![Basic::Ed25519.derive(self.key_manager.public_key()?)])
            .with_next_keys(vec![
                Basic::Ed25519.derive(self.key_manager.next_public_key()?)
            ])
            .with_witness_list(&initial_witness.unwrap_or_default())
            .build()?;

        let signed = icp.sign(
            vec![AttachedSignaturePrefix::new(
                SelfSigning::Ed25519Sha512,
                self.key_manager.sign(&icp.serialize()?)?,
                0,
            )],
            None,
        );

        self.processor
            .process(Message::Event(Box::new(signed.clone())))?;

        self.prefix = icp.event.get_prefix();

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
    pub fn incept_with_extra_keys(
        &mut self,
        extra_keys: impl IntoIterator<Item = (Basic, PublicKey)>,
    ) -> Result<SignedEventMessage, Error> {
        let mut keys: Vec<BasicPrefix> = extra_keys
            .into_iter()
            .map(|(key_type, key)| key_type.derive(key))
            .collect();
        // Signing key must be first
        keys.insert(0, Basic::Ed25519.derive(self.key_manager.public_key()?));
        let icp = EventMsgBuilder::new(EventTypeTag::Icp)
            .with_prefix(&self.prefix)
            .with_keys(keys)
            .with_next_keys(vec![
                Basic::Ed25519.derive(self.key_manager.next_public_key()?)
            ])
            .build()?;

        let signed = icp.sign(
            vec![AttachedSignaturePrefix::new(
                SelfSigning::Ed25519Sha512,
                self.key_manager.sign(&icp.serialize()?)?,
                0,
            )],
            None,
        );
        self.processor
            .process(Message::Event(Box::new(signed.clone())))?;
        self.prefix = icp.event.get_prefix();

        Ok(signed)
    }

    /// Interacts with peer identifier via generation of a `Seal`
    /// Seal gets added to our KEL db and returned back as `SignedEventMessage`
    ///
    pub fn interact(&self, peer: IdentifierPrefix) -> Result<SignedEventMessage, Error> {
        let next_sn = match self.processor.db.get_kel_finalized_events(&self.prefix) {
            Some(mut events) => match events.next_back() {
                Some(db_event) => db_event.signed_event_message.event_message.event.get_sn() + 1,
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
        let event = Event::new(
            self.prefix.clone(),
            next_sn,
            EventData::Ixn(InteractionEvent::new(pref, vec![seal])),
        )
        .to_message(SerializationFormats::JSON, &SelfAddressing::Blake3_256)?;
        let serialized = event.serialize()?;
        let signature = self.key_manager.sign(&serialized)?;
        let asp = AttachedSignaturePrefix::new(
            SelfSigning::ECDSAsecp256k1Sha256,
            signature,
            0, // TODO: what is this?
        );
        let signed = SignedEventMessage::new(&event, vec![asp], None);
        self.processor
            .db
            .add_kel_finalized_event(signed.clone(), &self.prefix)?;
        Ok(signed)
    }

    pub fn rotate(&mut self) -> Result<SignedEventMessage, Error> {
        self.key_manager.rotate()?;
        let rot = self.make_rotation()?;
        let rot = rot.sign(
            vec![AttachedSignaturePrefix::new(
                SelfSigning::Ed25519Sha512,
                self.key_manager.sign(&rot.serialize()?)?,
                0,
            )],
            None,
        );

        self.processor
            .process(Message::Event(Box::new(rot.clone())))?;

        Ok(rot)
    }

    fn make_rotation(&self) -> Result<EventMessage<KeyEvent>, Error> {
        let state = self
            .processor
            .compute_state(&self.prefix)?
            .ok_or_else(|| Error::SemanticError("There is no state".into()))?;
        EventMsgBuilder::new(EventTypeTag::Rot)
            .with_prefix(&self.prefix)
            .with_sn(state.sn + 1)
            .with_previous_event(&state.last_event_digest)
            .with_keys(vec![Basic::Ed25519.derive(self.key_manager.public_key()?)])
            .with_next_keys(vec![
                Basic::Ed25519.derive(self.key_manager.next_public_key()?)
            ])
            .build()
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
            .ok_or_else(|| Error::SemanticError("There is no state".into()))?;

        let ev = EventMsgBuilder::new(EventTypeTag::Ixn)
            .with_prefix(&self.prefix)
            .with_sn(state.sn + 1)
            .with_previous_event(&state.last_event_digest)
            .with_seal(seal_list)
            .build()?;

        let ixn = ev.sign(
            vec![AttachedSignaturePrefix::new(
                SelfSigning::Ed25519Sha512,
                self.key_manager.sign(&ev.serialize()?)?,
                0,
            )],
            None,
        );

        self.processor
            .process(Message::Event(Box::new(ixn.clone())))?;

        Ok(ixn)
    }

    /// Process and respond to single event
    ///
    pub fn respond_single(&self, msg: &[u8]) -> Result<(IdentifierPrefix, Vec<u8>), Error> {
        let parsed = signed_message(msg).map_err(|e| Error::DeserializeError(e.to_string()))?;
        match Message::try_from(parsed.1) {
            Err(e) => Err(Error::DeserializeError(e.to_string())),
            Ok(event) => match self.processor.process(event)? {
                None => Err(Error::InvalidIdentifierStat),
                Some(state) => Ok((state.prefix.clone(), serde_json::to_vec(&state)?)),
            },
        }
    }

    pub fn respond(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let events = signed_event_stream(msg)
            .map_err(|e| Error::DeserializeError(e.to_string()))?
            .1;

        let (processed_ok, _processed_failed): (Vec<_>, Vec<_>) = events
            .into_iter()
            .map(|event| {
                let message = Message::try_from(event)?;
                self.processor.process(message.clone()).map(|_| message)
            })
            .partition(Result::is_ok);

        let response: Vec<u8> = processed_ok
            .into_iter()
            .map(Result::unwrap)
            .map(|des_event| -> Result<Vec<u8>, Error> {
                match des_event {
                    Message::Event(ev) => {
                        let mut buf = vec![];
                        if let EventData::Icp(_) = ev.event_message.event.get_event_data() {
                            if !self.processor.has_receipt(
                                &self.prefix,
                                0,
                                &ev.event_message.event.get_prefix(),
                            )? {
                                buf.append(
                                    &mut self.processor.get_kerl(&self.prefix)?.ok_or_else(
                                        || Error::SemanticError("KEL is empty".into()),
                                    )?,
                                )
                            }
                        }
                        let rcp: SignedEventData = self.make_rct(ev.event_message)?.into();
                        buf.append(&mut rcp.to_cesr().unwrap());
                        Ok(buf)
                    }
                    Message::TransferableRct(_rct) => Ok(vec![]),
                    // TODO: this should process properly
                    _ => todo!(),
                }
            })
            .filter_map(|x| x.ok())
            .flatten()
            .collect();
        Ok(response)
    }

    pub fn make_rct(
        &self,
        event: EventMessage<KeyEvent>,
    ) -> Result<SignedTransferableReceipt, Error> {
        let ser = event.serialize()?;
        let signature = self.key_manager.sign(&ser)?;
        let validator_event_seal = self
            .processor
            .get_last_establishment_event_seal(&self.prefix)?
            .ok_or_else(|| Error::SemanticError("No establishment event seal".into()))?;
        let rcp = Receipt {
            prefix: event.event.get_prefix(),
            sn: event.event.get_sn(),
            receipted_event_digest: SelfAddressing::Blake3_256.derive(&ser),
        }
        .to_message(SerializationFormats::JSON)?;

        let signatures = vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )];
        let signed_rcp = SignedTransferableReceipt::new(rcp, validator_event_seal, signatures);

        self.processor
            .process(Message::TransferableRct(Box::new(signed_rcp.clone())))?;

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
    pub fn make_ntr(
        &self,
        message: EventMessage<KeyEvent>,
    ) -> Result<SignedNontransferableReceipt, Error> {
        let our_bp = match &self.prefix {
            IdentifierPrefix::Basic(prefix) => prefix,
            _ => {
                return Err(Error::SemanticError(
                    "we are not a witness - our prefix is not Basic".into(),
                ))
            }
        };
        match &message.event.get_event_data() {
            // ICP requires check if we are in initial witnesses only
            EventData::Icp(evt) => {
                if !evt.witness_config.initial_witnesses.contains(our_bp) {
                    return Err(Error::SemanticError("we are not in a witness list.".into()));
                }
                self.generate_ntr(message)
            }
            EventData::Rot(evt) => {
                if !evt.witness_config.prune.contains(our_bp) {
                    if evt.witness_config.graft.contains(our_bp) {
                        // FIXME: logic for already witnessed identifier required
                        self.generate_ntr(message)
                    } else {
                        Err(Error::SemanticError(
                            "event does not change our status as a witness".into(),
                        ))
                    }
                } else if evt.witness_config.prune.contains(our_bp) {
                    self.processor
                        .db
                        .remove_receipts_nt(&message.event.get_prefix())?;
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

    fn generate_ntr(
        &self,
        message: EventMessage<KeyEvent>,
    ) -> Result<SignedNontransferableReceipt, Error> {
        let signature;
        signature = self.key_manager.sign(&message.serialize()?)?;
        let bp = BasicPrefix::new(Basic::Ed25519, self.key_manager.public_key()?);
        let ssp = SelfSigningPrefix::new(SelfSigning::Ed25519Sha512, signature);
        let rcp = Receipt {
            prefix: message.event.get_prefix(),
            sn: message.event.get_sn(),
            receipted_event_digest: SelfAddressing::Blake3_256.derive(&message.serialize()?),
        }
        .to_message(SerializationFormats::JSON)?;
        let ntr = SignedNontransferableReceipt::new(&rcp, vec![(bp, ssp)]);
        self.processor
            .db
            .add_receipt_nt(ntr.clone(), &message.event.get_prefix())?;
        Ok(ntr)
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
