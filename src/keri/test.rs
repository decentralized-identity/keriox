#[cfg(test)]
use crate::{
    database::sled::SledEventDatabase,
    error::Error,
    keri::Keri,
    prefix::IdentifierPrefix,
    signer::CryptoBox,
};

#[test]
fn test_direct_mode() -> Result<(), Error> {
    use tempfile::Builder;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    std::fs::create_dir_all(root.path()).unwrap();
    let db = SledEventDatabase::new(root.path()).unwrap();

    // Init alice.
    let mut alice = Keri::new(db, CryptoBox::new()?, IdentifierPrefix::default())?;
    assert_eq!(alice.get_state()?, None);

    // Init bob.
    let mut bob = Keri::new(db, CryptoBox::new()?, IdentifierPrefix::default())?;
    bob.incept()?;
    assert_eq!(bob.get_state()?.unwrap().sn, 0);

    // Get alice's inception event.
    let mut msg_to_bob = alice.incept()?.serialize()?;

    // Send it to bob.
    let mut msg_to_alice = bob.respond(&msg_to_bob)?;
    {
        // Check if bob's state of alice is the same as current alice state.
        let alice_state_in_bob = bob.get_state_for_prefix(&alice.prefix)?.unwrap();
        assert_eq!(alice_state_in_bob, alice.get_state()?.unwrap());
    }

    // Send message from bob to alice and get alice's receipts.
    msg_to_bob = alice.respond(&msg_to_alice)?;

    {
        // Check if alice's state of bob is the same as current bob state.
        let bob_state_in_alice = alice.get_state_for_prefix(&bob.prefix)?.unwrap();
        assert_eq!(bob_state_in_alice, bob.get_state()?.unwrap());
    }

    // Send it to bob.
    bob.respond(&msg_to_bob)?;

    // Rotation event.
    let alice_rot = alice.rotate()?;
    assert_eq!(alice.get_state()?.unwrap().sn, 1);

    // Send rotation event to bob.
    msg_to_bob = alice_rot.serialize()?;
    msg_to_alice = bob.respond(&msg_to_bob)?;
    {
        // Check if bob's state of alice is the same as current alice state.
        let alice_state_in_bob = bob.get_state_for_prefix(&alice.prefix)?.unwrap();
        assert_eq!(alice_state_in_bob, alice.get_state()?.unwrap());
    }

    // Send bob's receipt to alice.
    alice.respond(&msg_to_alice)?;

    // Interaction event.
    let alice_ixn = alice.make_ixn(None)?;
    assert_eq!(alice.get_state()?.unwrap().sn, 2);

    // Send interaction event to bob.
    msg_to_bob = alice_ixn.serialize()?;
    msg_to_alice = bob.respond(&msg_to_bob)?;

    {
        // Check if bob's state of alice is the same as current alice state.
        let alice_state_in_bob = bob.get_state_for_prefix(&alice.prefix)?.unwrap();
        assert_eq!(alice_state_in_bob, alice.get_state()?.unwrap());
    }

    alice.respond(&msg_to_alice)?;

    Ok(())
}
