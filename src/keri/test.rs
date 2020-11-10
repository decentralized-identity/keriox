use crate::{error::Error, keri::Keri, prefix::Prefix};

#[test]
fn test_direct_mode() -> Result<(), Error> {
    // Init alice.
    let mut alice = Keri::new()?;
    assert_eq!(alice.get_state().sn, 0);
    assert_eq!(alice.kel.get_len(), 1);
    assert!(alice.other_instances.is_empty());
    assert!(alice.receipts.is_empty());
    assert!(alice.escrow_sigs.is_empty());

    // Init bob.
    let mut bob = Keri::new()?;
    assert_eq!(bob.get_state().sn, 0);
    assert_eq!(bob.get_log_len(), 1);
    assert!(bob.other_instances.is_empty());
    assert!(bob.receipts.is_empty());
    assert!(bob.escrow_sigs.is_empty());

    // Get alice's inception event.
    let mut msg_to_bob = alice.get_last_event();

    // Send it to bob.
    let mut msg_to_alice = bob.process_events(&msg_to_bob.as_bytes())?;
    {
        // Check if bob's state of alice is the same as current alice state.
        let alice_state_in_bob = bob
            .other_instances
            .get(&alice.get_state().prefix.to_str())
            .unwrap();
        assert_eq!(*alice_state_in_bob, alice.get_state());
    }

    // Send message from bob to alice and get alice's receipts.
    msg_to_bob = alice.process_events(&msg_to_alice.as_bytes())?;

    {
        // Check if alice's state of bob is the same as current bob state.
        let bob_state_in_alice = alice
            .other_instances
            .get(&bob.get_state().prefix.to_str())
            .unwrap();
        assert_eq!(*bob_state_in_alice, bob.get_state());
        assert_eq!(alice.receipts[&0].len(), 1);
    }

    // Send it to bob.
    bob.process_events(&msg_to_bob.as_bytes())?;
    assert_eq!(bob.receipts[&0].len(), 1);

    // Rotation event.
    alice.rotate()?;
    assert_eq!(alice.get_log_len(), 2);
    assert_eq!(alice.get_state().sn, 1);

    // Send rotation event to bob.
    msg_to_bob = alice.get_last_event();
    msg_to_alice = bob.process_events(&msg_to_bob.as_bytes())?;
    {
        // Check if bob's state of alice is the same as current alice state.
        let alice_state_in_bob = bob
            .other_instances
            .get(&alice.get_state().prefix.to_str())
            .unwrap();
        assert_eq!(*alice_state_in_bob, alice.get_state());
    }

    // Send bob's receipt to alice.
    alice.process_events(&msg_to_alice.as_bytes())?;
    assert_eq!(alice.receipts.len(), 2);
    assert_eq!(alice.escrow_sigs.len(), 0);

    // Interaction event.
    alice.make_ixn("")?;
    assert_eq!(alice.get_log_len(), 3);
    assert_eq!(alice.get_state().sn, 2);

    // Send interaction event to bob.
    msg_to_bob = alice.get_last_event();
    msg_to_alice = bob.process_events(&msg_to_bob.as_bytes())?;

    {
        // Check if bob's state of alice is the same as current alice state.
        let alice_state_in_bob = bob
            .other_instances
            .get(&alice.get_state().prefix.to_str())
            .unwrap();
        assert_eq!(*alice_state_in_bob, alice.get_state());
    }

    alice.process_events(&msg_to_alice.as_bytes())?;
    assert_eq!(alice.receipts.len(), 3);
    assert_eq!(alice.escrow_sigs.len(), 0);

    Ok(())
}
