use ursa::{
    keys::{PrivateKey, PublicKey},
    signatures::{ed25519, SignatureScheme},
};

use crate::{
    derivation::{basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning},
    error::Error,
    event::sections::nxt_commitment,
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, SelfAddressingPrefix},
    state::IdentifierState,
};

use super::event_msg_builder::{EventMsgBuilder, EventType};

/// Collects data for testing `IdentifierState` update. `prev_event_hash`, `sn`,
/// `current_keypair` and `new_keypair` are used to generate mock event message
/// of given type, `history_prefs` is used to check if any keypair used earlier
/// in event message sequence can verify current message.
#[derive(Debug)]
pub struct TestStateData {
    state: IdentifierState,
    prefix: IdentifierPrefix,
    keys_history: Vec<BasicPrefix>,
    prev_event_hash: SelfAddressingPrefix,
    sn: u64,
    current_keypair: (PublicKey, PrivateKey),
    new_keypair: (PublicKey, PrivateKey),
}

/// Create initial `TestStateData`, before application of any Event.
/// Provides only keypair for next event.
fn get_initial_test_data() -> Result<TestStateData, Error> {
    let ed = ed25519::Ed25519Sha512::new();

    // Get initial ed25519 keypair.
    let keypair = ed
        .keypair(Option::None)
        .map_err(|e| Error::CryptoError(e))?;

    Ok(TestStateData {
        state: IdentifierState::default(),
        prefix: IdentifierPrefix::default(),
        keys_history: vec![],
        prev_event_hash: SelfAddressingPrefix::default(),
        sn: 0,
        current_keypair: keypair.clone(),
        new_keypair: keypair.clone(),
    })
}

/// Construct mock event message from `event_type` and `state_data`, apply it to
/// `IdentifierState` in `state_data.state` and check if it was updated correctly.
fn test_update_identifier_state(
    event_type: EventType,
    state_data: TestStateData,
) -> Result<TestStateData, Error> {
    // Get current and next key_pairs from argument.
    let (mut cur_pk, mut cur_sk) = state_data.current_keypair;
    let (mut next_pk, mut next_sk) = state_data.new_keypair;

    // If event is establishment event, rotate keypair.
    let ed = ed25519::Ed25519Sha512::new();
    if event_type.is_establishment_event() {
        cur_pk = next_pk.clone();
        cur_sk = next_sk.clone();
        let next_keypair = ed
            .keypair(Option::None)
            .map_err(|e| Error::CryptoError(e))?;
        next_pk = next_keypair.0;
        next_sk = next_keypair.1;
    };

    let current_key_pref = Basic::Ed25519.derive(cur_pk.clone());
    let next_key_prefix = Basic::Ed25519.derive(next_pk.clone());
    let next_dig = nxt_commitment(1, &[next_key_prefix.clone()], SelfAddressing::Blake3_256);


    // Build event msg of given type.
    let event_msg = EventMsgBuilder::new(event_type.clone())?
        .with_sn(state_data.sn)
        .with_previous_event(state_data.prev_event_hash)
        .with_prefix(state_data.prefix.clone())
        .with_keys(vec![current_key_pref.clone()])
        .with_next_keys(vec![next_key_prefix])
        .build()?;
    let prefix = event_msg.event.prefix.clone();

    // Serialize event message before signing.
    let sed = event_msg.serialize()?;

    let attached_sig = {
        // Sign.
        let sig = ed.sign(&sed, &cur_sk).map_err(|e| Error::CryptoError(e))?;
        AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, sig, 0)
    };

    // Attach sign to event message.
    let signed_event = event_msg.sign(vec![attached_sig.clone()]);

    println!("{}", String::from_utf8(signed_event.serialize()?).unwrap());

    // Apply event to current IdentifierState.
    let new_state = state_data.state.apply(&signed_event)?;

    assert!(new_state.current.verify(&sed, &signed_event.signatures)?);

    // Check if current key prefix can verify message and signature.
    assert!(current_key_pref.verify(&sed, &attached_sig.signature)?);

    // If generated event is establishment event, check if any of previous
    // keys can verify message and signature.
    if event_type.is_establishment_event() {
        for old_key in state_data.keys_history.clone() {
            assert!(old_key.verify(&sed, &attached_sig.signature).is_err())
        }
    };

    // Check if state is updated correctly.
    assert_eq!(new_state.prefix, prefix.clone());
    assert_eq!(new_state.sn, state_data.sn);
    assert_eq!(new_state.last, sed);
    assert_eq!(new_state.current.public_keys.len(), 1);
    assert_eq!(new_state.current.public_keys[0], current_key_pref);
    assert_eq!(new_state.current.threshold, 1);
    assert_eq!(new_state.current.threshold_key_digest, next_dig);
    assert_eq!(new_state.witnesses, vec![]);
    assert_eq!(new_state.tally, 0);
    assert_eq!(new_state.delegates, vec![]);

    let mut new_history = state_data.keys_history.clone();
    // If event_type is establishment event, append current prefix to prefixes
    // history. It will be obsolete in the future establishement events.
    if event_type.is_establishment_event() {
        new_history.push(current_key_pref);
    }
    // Current event will be previous event for the next one, so return its hash.
    let prev_event_hash = SelfAddressing::Blake3_256.derive(&sed);
    // Compute sn for next event.
    let next_sn = state_data.sn + 1;

    Ok(TestStateData {
        state: new_state,
        prefix: prefix,
        keys_history: new_history,
        prev_event_hash,
        sn: next_sn,
        current_keypair: (cur_pk, cur_sk),
        new_keypair: (next_pk, next_sk),
    })
}

/// For given sequence of EventTypes check wheather `IdentifierState` is updated correctly
/// by applying `test_update_identifier_state` sequentially.
pub fn test_mock_event_sequence(sequence: Vec<EventType>) -> Result<TestStateData, Error> {
    let mut st = get_initial_test_data();

    let step = |event_type, state_data: Result<TestStateData, Error>| {
        test_update_identifier_state(event_type, state_data?)
    };
    for event_type in sequence {
        st = step(event_type, st);
    }
    st
}
