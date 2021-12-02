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

    bob.incept().unwrap();
    let bob_state = bob.get_state()?;
    assert_eq!(bob_state.unwrap().sn, 0);

    // Get alice's inception event.
    let alice_incepted = alice.incept()?;
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

    use crate::{derivation::self_signing::SelfSigning, event::EventMessage, prefix::{AttachedSignaturePrefix, Prefix}, query::{Envelope, MessageType, SignedEnvelope, query::{IdData, QueryData}, Route}, signer::KeyManager};

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    std::fs::create_dir_all(root.path()).unwrap();
    // Use one db for both, alice and bob to avoid sending their events between
    // each other, just have all in one place.
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());

    let alice_key_manager = Arc::new(Mutex::new(
        {
            use crate::signer::CryptoBox;
            CryptoBox::new()?
        }
    ));

    // Init alice.
    let mut alice = Keri::new(
        Arc::clone(&db),
        Arc::clone(&alice_key_manager))?;

    let bob_key_manager =
    {
            use crate::signer::CryptoBox;
            CryptoBox::new()?
    };

    // Init bob.
    let mut bob = Keri::new(
        Arc::clone(&db),
        Arc::new(Mutex::new(bob_key_manager)))?;

    bob.incept().unwrap();
    bob.rotate().unwrap();

    let bob_pref = bob.prefix();
    println!("bobs pref: {}\n", bob_pref.to_str());

    alice.incept()?;
    let alice_pref = alice.prefix();

    // construct qry message, to ask of bob key state message
    let vs = "KERI10JSON00011c_".parse()?;
    let message = MessageType::Qry(QueryData { reply_route: "route".into(), data: IdData {i : bob_pref.to_owned()} });
    let qry = EventMessage { 
        serialization_info: vs, 
        event: Envelope { 
            timestamp: "2020-08-22T17:50:12.988921+00:00".parse().unwrap(), 
            route: Route::Ksn,
            message
        }
    };

    // sign message by alice
    let signature = AttachedSignaturePrefix::new(
        SelfSigning::Ed25519Sha512,
        Arc::clone(&alice_key_manager)
            .lock()
            .unwrap()
            .sign(&serde_json::to_vec(&qry).unwrap())?, 
        0
    );
    let s = SignedEnvelope::new(qry, alice_pref.to_owned(), vec![signature]);

    // ask bob about bobs's key state notice
    let rep = bob.process_envelope(s)?;
    println!("{}", String::from_utf8(rep).unwrap());

    Ok(())
}