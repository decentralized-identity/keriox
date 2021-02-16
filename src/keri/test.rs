use std::fs;

use crate::{
    database::lmdb::LmdbEventDatabase,
    error::Error,
    keri::Keri,
    prefix::{IdentifierPrefix, Prefix},
    signer::CryptoBox,
};

#[test]
fn test_direct_mode() -> Result<(), Error> {
    use tempfile::Builder;

    // Create test db and event processor.
    let alices_root = Builder::new().prefix("test-db").tempdir().unwrap();
    let bobs_root = Builder::new().prefix("test-db2").tempdir().unwrap();
    fs::create_dir_all(alices_root.path()).unwrap();
    let alices_db = LmdbEventDatabase::new(alices_root.path()).unwrap();
    let bobs_db = LmdbEventDatabase::new(bobs_root.path()).unwrap();

    // Init alice.
    let mut alice = Keri::new(alices_db, CryptoBox::new()?, IdentifierPrefix::default())?;
    assert_eq!(alice.get_state()?, None);

    // Init bob.
    let mut bob = Keri::new(bobs_db, CryptoBox::new()?, IdentifierPrefix::default())?;
    bob.incept()?;
    assert_eq!(bob.get_state()?.unwrap().sn, 0);
    assert_eq!(bob.get_log_len(), 1);

    // Get alice's inception event.
    let mut msg_to_bob = String::from_utf8(alice.incept()?.serialize()?).unwrap();
    assert_eq!(alice.get_log_len(), 1);

    // Send it to bob.
    let mut msg_to_alice = bob.process_events(&msg_to_bob.as_bytes())?;
    {
        // Check if bob's state of alice is the same as current alice state.
        let alice_state_in_bob = bob.get_state_for_prefix(&alice.prefix)?.unwrap();
        assert_eq!(alice_state_in_bob, alice.get_state()?.unwrap());
    }

    // Send message from bob to alice and get alice's receipts.
    msg_to_bob = alice.process_events(&msg_to_alice.as_bytes())?;

    {
        // Check if alice's state of bob is the same as current bob state.
        let bob_state_in_alice = alice.get_state_for_prefix(&bob.prefix)?.unwrap();
        assert_eq!(bob_state_in_alice, bob.get_state()?.unwrap());
    }

    // Send it to bob.
    bob.process_events(&msg_to_bob.as_bytes())?;

    // Rotation event.
    let alice_rot = alice.rotate()?;
    assert_eq!(alice.get_log_len(), 2);
    assert_eq!(alice.get_state()?.unwrap().sn, 1);

    // Send rotation event to bob.
    msg_to_bob = String::from_utf8(alice_rot.serialize()?).unwrap();
    msg_to_alice = bob.process_events(&msg_to_bob.as_bytes())?;
    {
        // Check if bob's state of alice is the same as current alice state.
        let alice_state_in_bob = bob.get_state_for_prefix(&alice.prefix)?.unwrap();
        assert_eq!(alice_state_in_bob, alice.get_state()?.unwrap());
    }

    // Send bob's receipt to alice.
    alice.process_events(&msg_to_alice.as_bytes())?;

    // Interaction event.
    let alice_ixn = alice.make_ixn("")?;
    assert_eq!(alice.get_log_len(), 3);
    assert_eq!(alice.get_state()?.unwrap().sn, 2);

    // Send interaction event to bob.
    msg_to_bob = String::from_utf8(alice_ixn.serialize()?).unwrap();
    msg_to_alice = bob.process_events(&msg_to_bob.as_bytes())?;

    {
        // Check if bob's state of alice is the same as current alice state.
        let alice_state_in_bob = bob.get_state_for_prefix(&alice.prefix)?.unwrap();
        assert_eq!(alice_state_in_bob, alice.get_state()?.unwrap());
    }

    alice.process_events(&msg_to_alice.as_bytes())?;

    Ok(())
}
