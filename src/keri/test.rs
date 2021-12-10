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

mod witness {
    use std::sync::Arc;

    use crate::{
        derivation::{basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning},
        event::{EventMessage, SerializationFormats},
        prefix::{BasicPrefix, IdentifierPrefix},
        processor::EventProcessor,
        query::{
            key_state_notice::KeyStateNotice,
            new_reply,
            Route, SignedReply,
        },
        signer::{CryptoBox, KeyManager}, error::Error, database::sled::SledEventDatabase,
    };
    use tempfile::Builder;
    pub struct Witness {
        pub prefix: BasicPrefix,
        signer: CryptoBox,
        pub processor: EventProcessor,
    }

    impl Witness {
        pub fn new() -> Result<Self, Error> {
            let signer = CryptoBox::new()?;
            let processor = {
                let root = Builder::new().prefix("test-db").tempdir().unwrap();
                std::fs::create_dir_all(root.path()).unwrap();
                let witness_db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
                EventProcessor::new(witness_db.clone())
            };
            let prefix = Basic::Ed25519.derive(signer.public_key());
            Ok(Self {
                prefix,
                signer,
                processor,
            })
        }

        pub fn get_ksn_for_prefix(
            &self,
            prefix: &IdentifierPrefix,
        ) -> Result<SignedReply, Error> {
            let state = self.processor.compute_state(prefix).unwrap().unwrap();
            let ksn = EventMessage::<KeyStateNotice>::new_ksn(
                state,
                SerializationFormats::JSON,
                SelfAddressing::Blake3_256,
            );
            let rpy = new_reply(
                ksn,
                Route::ReplyKsn(IdentifierPrefix::Basic(self.prefix.clone())),
                SelfAddressing::Blake3_256,
            );

            let signature =
                SelfSigning::Ed25519Sha512.derive(self.signer.sign(&rpy.serialize()?).unwrap());
            Ok(SignedReply::new_nontrans(rpy, self.prefix.clone(), signature))
        }
    }
}
// #[cfg(feature = "query")]
// #[test]
// fn test_qry_rpy() -> Result<(), Error> {
//     use tempfile::Builder;

//     use crate::{
//         derivation::{basic::Basic, self_signing::SelfSigning},
//         event::{EventMessage, SerializationFormats},
//         keys::PublicKey,
//         prefix::{AttachedSignaturePrefix, BasicPrefix, Prefix},
//         query::{
//             query::{IdData, QueryData},
//             reply::ReplyData,
//             Envelope, Route, SignedNontransReply, SignedQuery,
//         },
//         signer::KeyManager,
//     };

//     // Create test db and event processor.
//     let root = Builder::new().prefix("test-db").tempdir().unwrap();
//     std::fs::create_dir_all(root.path()).unwrap();
//     // Use one db for both, alice and bob to avoid sending their events between
//     // each other, just have all in one place.
//     let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
//     let root = Builder::new().prefix("test-db").tempdir().unwrap();
//     std::fs::create_dir_all(root.path()).unwrap();
//     let db2 = Arc::new(SledEventDatabase::new(root.path()).unwrap());

//     let root = Builder::new().prefix("test-db").tempdir().unwrap();
//     std::fs::create_dir_all(root.path()).unwrap();
//     let witness_db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
//     let witness_key_manager = Arc::new(Mutex::new({
//         use crate::signer::CryptoBox;
//         CryptoBox::new()?
//     }));

//     let mut witness = Keri::new(Arc::clone(&witness_db), Arc::clone(&witness_key_manager))?;
//     witness.incept(None)?;

//     println!("witness: {}", witness.prefix().to_str());
//     let witness_prefix = match witness.prefix() {
//         crate::prefix::IdentifierPrefix::Basic(bp) => bp.clone(),
//         _ => BasicPrefix::new(Basic::Ed25519, PublicKey::new(vec![])),
//     };

//     let alice_key_manager = Arc::new(Mutex::new({
//         use crate::signer::CryptoBox;
//         CryptoBox::new()?
//     }));

//     // Init alice.
//     let mut alice = Keri::new(Arc::clone(&db), Arc::clone(&alice_key_manager))?;

//     let bob_key_manager = Arc::new(Mutex::new({
//         use crate::signer::CryptoBox;
//         CryptoBox::new()?
//     }));

//     // Init bob.
//     let mut bob = Keri::new(Arc::clone(&db2), Arc::clone(&bob_key_manager))?;

//     let bob_icp = bob.incept(None).unwrap();
//     // bob.rotate().unwrap();

//     let bob_pref = bob.prefix();
//     println!("bobs pref: {}\n", bob_pref.to_str());

//     let alice_icp = alice.incept(Some(vec![witness_prefix.clone()]))?;
//     // send alices icp to witness
//     let rcps = witness.respond(&alice_icp.serialize()?)?;
//     // send bobs icp to witness to have his keys
//     let rcps = witness.respond(&bob_icp.serialize()?)?;

//     println!("\nrcps: {}\n", String::from_utf8(rcps).unwrap());
//     let alice_pref = alice.prefix();

//     // Bob asks about alices key state
//     // construct qry message, to ask of alice key state message
//     let message = QueryData {
//         reply_route: "route".into(),
//         data: IdData {
//             i: alice_pref.to_owned(),
//         },
//     };
//     let qry = Envelope::new(Route::Ksn, message).to_message(SerializationFormats::JSON)?;

//     // sign message by bob
//     let signature = AttachedSignaturePrefix::new(
//         SelfSigning::Ed25519Sha512,
//         Arc::clone(&bob_key_manager)
//             .lock()
//             .unwrap()
//             .sign(&serde_json::to_vec(&qry).unwrap())?,
//         0,
//     );
//     // Qry message signed by Bob
//     let s = SignedQuery::new(qry, bob_pref.to_owned(), vec![signature]);

//     // ask witness about alice's key state notice
//     let rep = witness.process_signed_query(s)?;

//     // sign message by witness
//     let signature =
//         SelfSigning::Ed25519Sha512.derive(witness.key_manager().lock().unwrap().sign(&rep)?);

//     // reply with ksn inside
//     let rp: EventMessage<Envelope<ReplyData>> =
//         serde_json::from_str(&String::from_utf8(rep).unwrap()).unwrap();
//     let signed = SignedNontransReply::new(rp, witness_prefix.to_owned(), signature);

//     // send reply message with ksn to bob
//     let rep = bob.processor.process_signed_reply(signed)?;

//     Ok(())
// }

#[cfg(feature = "query")]
#[test]
pub fn test_rpy_ksn() -> Result<(), Error> {
    use crate::{
        processor::EventProcessor,
        query::QueryError,
        signer::CryptoBox, prefix::Prefix,
    };
    use tempfile::Builder;
    use witness::Witness;

    let witness = Witness::new()?;

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
    println!("bobs pref: {}\n", bob_pref.to_str());

    // send bobs icp to witness to have his keys
    witness.processor.process_event(&bob_icp)?;

    // construct bobs ksn msg in rpy made by witness
    let signed_rpy = witness.get_ksn_for_prefix(&bob_pref)?;

    // Process reply message before having any bob's events in db.
    let res = alice.process_signed_reply(signed_rpy.clone());
    let escrow = alice.db.get_escrowed_replys(&bob_pref);
    assert_eq!(escrow.unwrap().collect::<Vec<_>>().len(), 1);
    assert!(matches!(
        res,
        Err(Error::MissingEventError)
    ));
    alice.process_event(&bob_icp)?;

    // rotate bob's keys. Let alice process his rotation. She will have most recent bob's event.
    let bob_rot = bob.rotate()?;
    witness.processor.process_event(&bob_rot)?;
    alice.process_event(&bob_rot)?;

    // try to process old reply message
    let res = alice.process_signed_reply(signed_rpy.clone());
    assert!(matches!(res, Err(Error::QueryError(QueryError::StaleKsn))));

    // now create new reply event by witness, and process it by alice.
    let new_reply = witness.get_ksn_for_prefix(&bob_pref)?;
    let res = alice.process_signed_reply(new_reply);
    assert!(res.is_ok());

    let new_bob_rot = bob.rotate()?;
    // Create transferable reply by bob and process it by alice.
    let trans_rpy = bob.get_ksn_for_prefix(&bob_pref)?;
    let res = alice.process_signed_reply(trans_rpy.clone());
    assert!(matches!(res, Err(Error::MissingEventError)));

    // Now update bob's state in alice's db to most recent.
    alice.process_event(&new_bob_rot)?;
    let res = alice.process_signed_reply(trans_rpy.clone());
    assert!(res.is_ok());

    Ok(())
}
