use crate::{
    database::EventDatabase,
    derivation::self_addressing::SelfAddressing,
    error::Error,
    event::sections::KeyConfig,
    event_message::{parse::message, SignedEventMessage},
    prefix::AttachedSignaturePrefix,
    prefix::IdentifierPrefix,
    state::IdentifierState,
};

pub struct EventProcessor<D: EventDatabase> {
    db: D,
}

pub struct Deserialized<'a, M> {
    raw: &'a [u8],
    deserialized: M,
}

pub trait Processable {
    fn verify_using(&self, kc: &KeyConfig) -> Result<bool, Error>;

    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error>;

    fn id(&self) -> &IdentifierPrefix;

    fn sn(&self) -> u64;

    fn raw(&self) -> &[u8];

    fn sigs(&self) -> &[AttachedSignaturePrefix];
}

impl Processable for Deserialized<'_, SignedEventMessage> {
    fn verify_using(&self, kc: &KeyConfig) -> Result<bool, Error> {
        kc.verify(self.raw, &self.deserialized.signatures)
    }

    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        state.apply(&self.deserialized)
    }

    fn id(&self) -> &IdentifierPrefix {
        &self.deserialized.event_message.event.prefix
    }

    fn sn(&self) -> u64 {
        self.deserialized.event_message.event.sn
    }

    fn raw(&self) -> &[u8] {
        &self.raw
    }

    fn sigs(&self) -> &[AttachedSignaturePrefix] {
        &self.deserialized.signatures
    }
}

impl<D: EventDatabase> EventProcessor<D> {
    pub fn new(db: D) -> Self {
        Self { db }
    }

    /// Compute State for Prefix
    ///
    /// Returns the current State associated with
    /// the given Prefix
    pub fn compute_state(&self, id: &IdentifierPrefix) -> Result<Option<IdentifierState>, Error> {
        // start with empty state
        let mut state = IdentifierState::default();

        // starting from inception
        for sn in 0.. {
            // read the latest raw event
            let raw = match self
                .db
                .last_event_at_sn(id, sn)
                .map_err(|_| Error::StorageError)?
            {
                Some(r) => r,
                None => {
                    if sn == 0 {
                        // no inception event, no state
                        return Ok(None);
                    } else {
                        // end of KEL, stop looping
                        break;
                    }
                }
            };
            // parse event
            // FIXME, DONT UNWRAP
            let parsed = message(&String::from_utf8(raw).unwrap()).unwrap().1;
            // apply it to the state
            // TODO avoid .clone()
            state = match state.clone().apply(&parsed) {
                Ok(s) => s,
                // will happen when a recovery has overridden some part of the KEL,
                // stop processing here
                Err(_) => break,
            }
        }

        Ok(Some(state))
    }

    pub fn process<E>(&self, event: &E) -> Result<IdentifierState, Error>
    where
        E: Processable,
    {
        let dig = SelfAddressing::Blake3_256.derive(event.raw());
        self.db
            .log_event(event.id(), &dig, event.raw(), event.sigs())
            .map_err(|_| Error::StorageError)?;
        // get state for id (TODO cache?)
        self.compute_state(event.id())
            // get empty state if there is no state yet
            .and_then(|opt| Ok(opt.map_or_else(|| IdentifierState::default(), |s| s)))
            // process the event update
            .and_then(|state| event.apply_to(state))
            // see why application failed and reject or escrow accordingly
            .map_err(|e| match e {
                Error::EventOutOfOrderError => {
                    match self
                        .db
                        .escrow_out_of_order_event(event.id(), event.sn(), &dig)
                    {
                        Err(_) => Error::StorageError,
                        _ => e,
                    }
                }
                Error::EventDuplicateError => {
                    match self.db.duplicitous_event(event.id(), event.sn(), &dig) {
                        Err(_) => Error::StorageError,
                        _ => e,
                    }
                }
                _ => e,
            })
            // verify the signatures on the event
            .and_then(|state| {
                event
                    .verify_using(&state.current)
                    // escrow partially signed event
                    .map_err(|e| match e {
                        Error::NotEnoughSigsError => {
                            match self.db.escrow_partially_signed_event(
                                event.id(),
                                event.sn(),
                                &dig,
                            ) {
                                Err(_) => Error::StorageError,
                                _ => e,
                            }
                        }
                        _ => e,
                    })?;
                self.db
                    .finalise_event(event.id(), event.sn(), &dig)
                    .map_err(|_| Error::StorageError)?;
                Ok(state)
            })
    }
}

#[test]
fn test_process() -> Result<(), Error> {
    use crate::database::lmdb::LmdbEventDatabase;
    use crate::event_message::parse::message;
    use std::fs;
    use tempfile::Builder;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();

    let db = LmdbEventDatabase::new(root.path()).unwrap();
    let event_processor = EventProcessor::new(db);

    // Create deserialized inception event from string.
    // Events and sigs are from keripy `test_multisig_digprefix` test.
    let deserialized_icp = {
        let icp_raw = r#"{"vs":"KERI10JSON000159_","pre":"ECui-E44CqN2U7uffCikRCp_YKLkPrA4jsTZ_A0XRLzc","sn":"0","ilk":"icp","sith":"2","keys":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"nxt":"Evhf3437ZRRnVhT0zOxo_rBX_GxpGoAnLuzrVlDK8ZdM","toad":"0","wits":[],"cnfg":[]}"#;
        let icp_sigs = vec![
            "AAJ66nrRaNjltE31FZ4mELVGUMc_XOqOAOXZQjZCEAvbeJQ8r3AnccIe1aepMwgoQUeFdIIQLeEDcH8veLdud_DQ",
            "ABTQYtYWKh3ScYij7MOZz3oA6ZXdIDLRrv0ObeSb4oc6LYrR1LfkICfXiYDnp90tAdvaJX5siCLjSD3vfEM9ADDA",
            "ACQTgUl4zF6U8hfDy8wwUva-HCAiS8LQuP7elKAHqgS8qtqv5hEj3aTjwE91UtgAX2oCgaw98BCYSeT5AuY1SpDA",
        ];
        let msg = message(icp_raw).unwrap().1;
        let sigs = icp_sigs.iter().map(|raw| raw.parse().unwrap()).collect();
        Deserialized {
            raw: &msg.serialize().unwrap(),
            deserialized: msg.sign(sigs),
        }
    };

    // Process icp event.
    let id_state = event_processor.process(&deserialized_icp)?;
    assert_eq!(id_state.sn, 0);
    // Check if processed event is in kel.
    let icp_from_db = event_processor
        .db
        .last_event_at_sn(&deserialized_icp.deserialized.event_message.event.prefix, 0)
        .unwrap();
    assert_eq!(icp_from_db, Some(deserialized_icp.raw.to_vec()));

    // Create deserialized rotation event.
    let deserialized_rot = {
        let rot_raw = r#"{"vs":"KERI10JSON000198_","pre":"ECui-E44CqN2U7uffCikRCp_YKLkPrA4jsTZ_A0XRLzc","sn":"1","ilk":"rot","dig":"EF9THPxXUribmjC641JsDJynFJwieRTpDn-xvhxvXaPI","sith":"2","keys":["DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ","D1kcBE7h0ImWW6_Sp7MQxGYSshZZz6XM7OiUE5DXm0dU","D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM"],"nxt":"EwkvQoCtKlgZeQK1eUb8BfmaCLCVVC13jI-j-g7Qt5KY","toad":"0","cuts":[],"adds":[],"data":[]}"#;
        let rot_sigs = vec![
            "AAuEZp7-BaPscSZkKR-xFGbRj-vq5DQJBp5Fm9RKc1glep_2md7gMrGbEdJC3b2hGa_j-fyEFA_gze-ugRwYLCCw",
            "ABDoHupcc04lamZcZb3gm-3vpwA7VyIWolKOSmGfm9PRt1uh8mu--Cj4RQzo2mlY3s-GLlYKY_DK1SbZ5lOCUbDw",
            "ACCSgi9afM9B01aoMbYfSBNXnFsT5FiIM_g3mRvr8yOa6sItd4Issj8fZgZtkprGGxreXsbqKiEHim4pAWTdNWCg",
        ];
        let msg = message(rot_raw).unwrap().1;
        let sigs = rot_sigs.iter().map(|raw| raw.parse().unwrap()).collect();
        Deserialized {
            raw: &msg.serialize().unwrap(),
            deserialized: msg.sign(sigs),
        }
    };

    // Process rotation event.
    let id_state = event_processor.process(&deserialized_rot)?;
    assert_eq!(id_state.sn, 1);
    // Check if processed event is in db.
    let rot_from_db = event_processor
        .db
        .last_event_at_sn(&deserialized_rot.deserialized.event_message.event.prefix, 1)
        .unwrap();
    assert_eq!(rot_from_db, Some(deserialized_rot.raw.to_vec()));

    // Process the same rotation event one more time.
    let id_state = event_processor.process(&deserialized_rot);
    assert!(id_state.is_err());
    assert!(matches!(id_state, Err(Error::EventDuplicateError)));

    // Construct partially signed interaction event.
    let deserialized_ixn = {
        let ixn_raw = r#"{"vs":"KERI10JSON0000a3_","pre":"ECui-E44CqN2U7uffCikRCp_YKLkPrA4jsTZ_A0XRLzc","sn":"2","ilk":"ixn","dig":"E0d-mZATnsQJcsbMftEZTxckCOBpSO8HVZHBBNTg2P9Q","data":[]}"#;
        let ixn_sigs = vec![
        "AAriQOdH87Tv5Axbhk1fgDXgXWv1oAGyxaW-0de6Z3CtRGDpfJgquxFhYROi7Fa-AHf8OXfaeLObcUS03xNSlOCQ",
        "ABb8fE50SRZkSfqlFZoGOkusCl_ed3JLt1kr22KnYnUC63ykNjpyAVJpmFISo7McV8QAr10xrYzSY5C6xbgJGnAw",
        "ACAmnpfoxmrR9xhX61nn-oYtuJ_iNiotDKKdAHRK8Qm87GcGF6M9RcFD7XFci7czpsXLMHXnH5mM8WXpW4FDuYCw",
        ];
        let msg = message(ixn_raw).unwrap().1;
        // Sign event with 1 of 3 signatures.
        let sigs = vec![ixn_sigs[0].parse().unwrap()];
        Deserialized {
            raw: &msg.serialize().unwrap(),
            deserialized: msg.sign(sigs),
        }
    };

    // Process interaction event.
    let id_state = event_processor.process(&deserialized_ixn);
    assert!(matches!(id_state, Err(Error::NotEnoughSigsError)));

    // Check if processed ixn event is in kel. It shouldn't because of not enough signatures.
    let ixn_from_db = event_processor
        .db
        .last_event_at_sn(&deserialized_ixn.deserialized.event_message.event.prefix, 2);
    assert!(matches!(ixn_from_db, Ok(None)));

    // Out of order event.
    let out_of_order_ixn = {
        let out_of_order_ixn_raw = r#"{"vs":"KERI10JSON0000a3_","pre":"ECui-E44CqN2U7uffCikRCp_YKLkPrA4jsTZ_A0XRLzc","sn":"5","ilk":"ixn","dig":"EwiIGwOHz-mXTM9q7UHjILuj2rs3GESAbrLJiZP1u-ug","data":[]}"#;
        let out_of_order_sigs = vec![
            "AA5WWCK-bVduSseQBSRsDoy0LeXk8VcZXZGawUTYYkcTrkdYIxSXHecUvAHoOdGN1H0QJXuQJEAkLlEN1Y7g_1Cw",
            "AB1e-eIsZTdyKGLMBI_Aig3-pf3l5BmUyi12coRusyExZoMcO5SSokaeZgRMZRb6ncDk7iSRylaKeq5iBhmDmGBw",
            "ACOdWDJWMh1EHvco3ndqwBhJBkoT6PcYJenls6xcNuB9yHbkGuZPuhHMAYHRD60sBxTbrEf28AvAW60sZPYl_JAA",
        ];
        let msg = message(out_of_order_ixn_raw).unwrap().1;
        let sigs = out_of_order_sigs
            .iter()
            .map(|raw| raw.parse().unwrap())
            .collect();
        Deserialized {
            raw: &msg.serialize().unwrap(),
            deserialized: msg.sign(sigs),
        }
    };

    let id_state = event_processor.process(&out_of_order_ixn);
    assert!(id_state.is_err());
    assert!(matches!(id_state, Err(Error::EventOutOfOrderError)));

    // Check if processed event is in kel. It shouldn't.
    let ixn_from_db = event_processor
        .db
        .last_event_at_sn(&out_of_order_ixn.deserialized.event_message.event.prefix, 5);
    assert!(matches!(ixn_from_db, Ok(None)));

    Ok(())
}
