#[cfg(feature = "wallet")]
use universal_wallet::prelude::UnlockedWallet;

#[cfg(test)]
use crate::{database::sled::SledEventDatabase, error::Error, keri::Keri};

use std::sync::{Arc, Mutex};

#[test]
fn test_direct_mode() -> Result<(), Error> {
    use tempfile::Builder;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    std::fs::create_dir_all(root.path()).unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());

    let alice_key_manager = {
        #[cfg(feature = "wallet")]
        {
            let mut alice_key_manager = UnlockedWallet::new("alice");
            crate::signer::wallet::incept_keys(&mut alice_key_manager)?;
            Arc::new(Mutex::new(alice_key_manager))
        }
        #[cfg(not(feature = "wallet"))]
        {
            use crate::signer::CryptoBox;
            Arc::new(Mutex::new(CryptoBox::new()?))
        }
    };

    // Init alice.
    let mut alice = Keri::new(Arc::clone(&db), alice_key_manager.clone())?;

    assert_eq!(alice.get_state()?, None);

    //lazy_static! {
    //  static ref BK: Arc<Mutex<dyn KeyManager>> = {
    let bob_key_manager = {
        #[cfg(feature = "wallet")]
        {
            let mut bob_key_manager = UnlockedWallet::new("alice");
            crate::signer::wallet::incept_keys(&mut bob_key_manager)?;
            Arc::new(Mutex::new(bob_key_manager))
        }
        #[cfg(not(feature = "wallet"))]
        {
            use crate::signer::CryptoBox;
            Arc::new(Mutex::new(CryptoBox::new().unwrap()))
        }
    };
    //}

    // Init bob.
    let mut bob = Keri::new(Arc::clone(&db), bob_key_manager.clone())?;

    bob.incept(None).unwrap();
    let bob_state = bob.get_state()?;
    assert_eq!(bob_state.unwrap().sn, 0);

    // Get alice's inception event.
    let alice_incepted = alice.incept(None)?;
    let mut msg_to_bob = alice_incepted.serialize()?;

    // Send it to bob.
    let mut msg_to_alice = bob.respond(&msg_to_bob)?;

    // Check if bob's state of alice is the same as current alice state.
    let alice_state_in_bob = bob.get_state_for_prefix(&alice.prefix)?.unwrap();
    assert_eq!(alice_state_in_bob, alice.get_state()?.unwrap());

    // Send message from bob to alice and get alice's receipts.
    msg_to_bob = alice.respond(&msg_to_alice)?;

    // Check if alice's state of bob is the same as current bob state.
    let bob_state_in_alice = alice.get_state_for_prefix(&bob.prefix)?.unwrap();
    assert_eq!(bob_state_in_alice, bob.get_state()?.unwrap());

    // Send it to bob.
    bob.respond(&msg_to_bob)?;

    // Rotation event.
    let alice_rot = alice.rotate()?;
    assert_eq!(alice.get_state()?.unwrap().sn, 1);

    // Send rotation event to bob.
    msg_to_bob = alice_rot.serialize()?;
    msg_to_alice = bob.respond(&msg_to_bob)?;
    // Check if bob's state of alice is the same as current alice state.
    let alice_state_in_bob = bob.get_state_for_prefix(&alice.prefix)?.unwrap();
    assert_eq!(alice_state_in_bob, alice.get_state()?.unwrap());

    // Send bob's receipt to alice.
    alice.respond(&msg_to_alice)?;

    // Interaction event.
    let alice_ixn = alice.make_ixn(None)?;
    assert_eq!(alice.get_state()?.unwrap().sn, 2);

    // Send interaction event to bob.
    msg_to_bob = alice_ixn.serialize()?;
    msg_to_alice = bob.respond(&msg_to_bob)?;

    // Check if bob's state of alice is the same as current alice state.
    let alice_state_in_bob = bob.get_state_for_prefix(&alice.prefix)?.unwrap();
    assert_eq!(alice_state_in_bob, alice.get_state()?.unwrap());

    alice.respond(&msg_to_alice)?;

    Ok(())
}

#[cfg(feature = "query")]
#[test]
fn test_qry_rpy() -> Result<(), Error> {
    use tempfile::Builder;

    use crate::{
        derivation::self_signing::SelfSigning,
        event::SerializationFormats,
        prefix::AttachedSignaturePrefix,
        query::{
            query::{Query, SignedQuery},
            Route, ReplyType,
        },
        signer::KeyManager,
        keri::witness::Witness,
    };

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let alice_db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let bob_db = Arc::new(SledEventDatabase::new(root.path()).unwrap());

    let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
    let witness = Witness::new(witness_root.path())?;

    let alice_key_manager = Arc::new(Mutex::new({
        use crate::signer::CryptoBox;
        CryptoBox::new()?
    }));

    // Init alice.
    let mut alice = Keri::new(Arc::clone(&alice_db), Arc::clone(&alice_key_manager))?;

    let bob_key_manager = Arc::new(Mutex::new({
        use crate::signer::CryptoBox;
        CryptoBox::new()?
    }));

    // Init bob.
    let mut bob = Keri::new(Arc::clone(&bob_db), Arc::clone(&bob_key_manager))?;

    let bob_icp = bob.incept(None).unwrap();
    // bob.rotate().unwrap();

    let bob_pref = bob.prefix();

    let alice_icp = alice.incept(Some(vec![witness.prefix.clone()]))?;
    // send alices icp to witness
    let _rcps = witness.processor.process_event(&alice_icp)?;
    // send bobs icp to witness to have his keys
    let _rcps = witness.processor.process_event(&bob_icp)?;

    let alice_pref = alice.prefix();

    // Bob asks about alices key state
    // construct qry message to ask of alice key state message
    let qry = Query::new_query(Route::Ksn, alice_pref, SerializationFormats::JSON)?;

    // sign message by bob
    let signature = AttachedSignaturePrefix::new(
        SelfSigning::Ed25519Sha512,
        Arc::clone(&bob_key_manager)
            .lock()
            .unwrap()
            .sign(&serde_json::to_vec(&qry).unwrap())?,
        0,
    );
    // Qry message signed by Bob
    let s = SignedQuery::new(qry, bob_pref.to_owned(), vec![signature]);

    // ask witness about alice's key state notice
    let rep = witness.process_signed_query(s)?;
   
    match rep {
        ReplyType::Rep(rep) => {
            assert_eq!(&rep.reply.event.data.data.event.state, &alice.get_state().unwrap().unwrap())
        },
        ReplyType::Kel(_) => assert!(false),
    }

    Ok(())
}

#[cfg(feature = "query")]
#[test]
pub fn test_key_state_notice() -> Result<(), Error> {
    use crate::{
        processor::EventProcessor,
        query::QueryError,
        signer::CryptoBox, keri::witness::Witness,
    };
    use tempfile::Builder;

    let witness = {
        let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let path = witness_root.path();
        std::fs::create_dir_all(path).unwrap();
        Witness::new(path)?
    };

    // Init bob.
    let mut bob = {
        // Create test db and event processor.
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());

        let bob_key_manager = Arc::new(Mutex::new(CryptoBox::new()?));
        Keri::new(Arc::clone(&db), Arc::clone(&bob_key_manager))?
    };

    let alice = {
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        let db2 = Arc::new(SledEventDatabase::new(root.path()).unwrap());
        EventProcessor::new(db2)
    };

    let bob_icp = bob.incept(Some(vec![witness.prefix.clone()])).unwrap();
    // bob.rotate().unwrap();

    let bob_pref = bob.prefix().clone();

    // send bobs icp to witness to have his keys
    witness.processor.process_event(&bob_icp)?;

    // construct bobs ksn msg in rpy made by witness
    let signed_rpy = witness.get_ksn_for_prefix(&bob_pref)?;

    // Process reply message before having any bob's events in db.
    let res = alice.process_signed_reply(&signed_rpy.clone());
    assert!(matches!(
        res,
        Err(Error::QueryError(QueryError::OutOfOrderEventError))
    ));
    alice.process_event(&bob_icp)?;

    // rotate bob's keys. Let alice process his rotation. She will have most recent bob's event.
    let bob_rot = bob.rotate()?;
    witness.processor.process_event(&bob_rot)?;
    alice.process_event(&bob_rot)?;

    // try to process old reply message
    let res = alice.process_signed_reply(&signed_rpy.clone());
    assert!(matches!(res, Err(Error::QueryError(QueryError::StaleKsn))));

    // now create new reply event by witness and process it by alice.
    let new_reply = witness.get_ksn_for_prefix(&bob_pref)?;
    let res = alice.process_signed_reply(&new_reply);
    assert!(res.is_ok());

    let new_bob_rot = bob.rotate()?;
    witness.processor.process_event(&new_bob_rot)?;
    // Create transferable reply by bob and process it by alice.
    let trans_rpy = witness.get_ksn_for_prefix(&bob_pref)?;
    let res = alice.process_signed_reply(&trans_rpy.clone());
    assert!(matches!(res, Err(Error::QueryError(QueryError::OutOfOrderEventError))));

    // Now update bob's state in alice's db to most recent.
    alice.process_event(&new_bob_rot)?;
    let res = alice.process_signed_reply(&trans_rpy.clone());
    assert!(res.is_ok());

    Ok(())
}
