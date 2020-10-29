mod log_state;
use keri::{error::Error, event::event_data::EventData, prefix::Prefix};
use log_state::LogState;

#[test]
fn test_direct_mode() -> Result<(), Error> {
    // Init alice.
    let mut alice = LogState::new()?;
    assert_eq!(alice.state.sn, 0);
    assert_eq!(alice.get_log_len(), 1);
    assert!(matches!(
        alice.get_last_event().unwrap().event_message.event.event_data,
        EventData::Icp(_)
    ));
    assert!(alice.other_instances.is_empty());
    assert!(alice.receipts.is_empty());
    assert!(alice.escrow_sigs.is_empty());

    // Init bob.
    let mut bob = LogState::new()?;
    assert_eq!(bob.state.sn, 0);
    assert_eq!(bob.get_log_len(), 1);
    assert!(matches!(
        bob.get_last_event().unwrap().event_message.event.event_data,
        EventData::Icp(_)
    ));
    assert!(bob.other_instances.is_empty());
    assert!(bob.receipts.is_empty());
    assert!(bob.escrow_sigs.is_empty());

    // Serialize alice inception event.
    let mut msg_to_bob = alice.get_last_event().unwrap().serialize()?;

    // Simulate sending it to bob.
    let mut bob_receipts = bob.process_events(msg_to_bob);

    {
        // Check if bob's state of alice is the same as current alice state.
        let alice_state_in_bob = bob
            .other_instances
            .get(&alice.state.prefix.to_str())
            .unwrap();
        assert_eq!(*alice_state_in_bob, alice.state);
    }

    // Prepare message from bob to alice with bob's inception event and receipt.
    let mut receipts = bob_receipts
        .iter()
        .map(|x| x.serialize())
        .filter_map(Result::ok)
        .collect::<Vec<_>>()
        .concat();
    let mut msg_to_alice = bob.get_last_event().unwrap().serialize().unwrap();
    msg_to_alice.append(&mut receipts);

    // Send message from bob to alice and get alice's receipts.
    let alice_receipts = alice.process_events(msg_to_alice);
    assert_eq!(alice_receipts.len(), 1);

    {
        // Check if alice's state of bob is the same as current bob state.
        let bob_state_in_alice = alice
            .other_instances
            .get(&bob.state.prefix.to_str())
            .unwrap();
        assert_eq!(*bob_state_in_alice, bob.state);
        assert_eq!(alice.receipts.len(), 1);
    }

    // Prepare receipt message for bob.
    msg_to_bob = alice_receipts
        .iter()
        .map(|x| x.serialize())
        .filter_map(Result::ok)
        .collect::<Vec<_>>()
        .concat();

    // Send it to bob.
    bob.process_events(msg_to_bob);
    assert_eq!(bob.receipts.len(), 1);

    // Rotation event.
    alice.rotate()?;
    assert_eq!(alice.get_log_len(), 2);
    assert_eq!(alice.state.sn, 1);

    // Send rotation event to bob.
    msg_to_bob = alice.get_last_event().unwrap().serialize()?;
    bob_receipts = bob.process_events(msg_to_bob);
    {
        // Check if bob's state of alice is the same as current alice state.
        let alice_state_in_bob = bob
            .other_instances
            .get(&alice.state.prefix.to_str())
            .unwrap();
        assert_eq!(*alice_state_in_bob, alice.state);
        assert_eq!(alice.state.sn, 1);
        assert_eq!(alice.get_log_len(), 2);
    }
    msg_to_alice = bob_receipts
        .iter()
        .map(|x| x.serialize())
        .filter_map(Result::ok)
        .collect::<Vec<_>>()
        .concat();

    // Send bob's receipt to alice.
    alice.process_events(msg_to_alice);
    assert_eq!(alice.receipts.len(), 2);
    assert_eq!(alice.escrow_sigs.len(), 0);

    // Interaction event.
    alice.make_ixn("")?;
    assert_eq!(alice.get_log_len(), 3);
    assert_eq!(alice.state.sn, 2);

    // Send interaction event to bob.
    msg_to_bob = alice.get_last_event().unwrap().serialize()?;
    bob_receipts = bob.process_events(msg_to_bob);

    {
        // Check if bob's state of alice is the same as current alice state.
        let alice_state_in_bob = bob
            .other_instances
            .get(&alice.state.prefix.to_str())
            .unwrap();
        assert_eq!(*alice_state_in_bob, alice.state);
    }

    // Send bob's receipt to alice.
    msg_to_alice = bob_receipts
        .iter()
        .map(|x| x.serialize())
        .filter_map(Result::ok)
        .collect::<Vec<_>>()
        .concat();

    alice.process_events(msg_to_alice);
    assert_eq!(alice.receipts.len(), 3);
    assert_eq!(alice.escrow_sigs.len(), 0);

    Ok(())
}
