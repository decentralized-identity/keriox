use ursa::{
    keys::{PrivateKey, PublicKey},
    signatures::{ed25519, SignatureScheme},
};

use crate::{
    derivation::{basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning},
    error::Error,
    event::event_data::{inception::InceptionEvent, rotation::RotationEvent, EventData},
    event::sections::{InceptionWitnessConfig, KeyConfig, WitnessConfig},
    event::Event,
    event::SerializationFormats,
    prefix::{
        AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, Prefix, SelfAddressingPrefix,
    },
    state::IdentifierState,
};

pub enum EventType {
    Inception,
    Rotation,
}

/// Create mock event on given type. For now only inception and rotation events.
fn create_mock_event(
    event_type: EventType,
    sn: u64,
    prev_event: SelfAddressingPrefix,
    identifier: BasicPrefix,
    curr_key: BasicPrefix,
    nxt: SelfAddressingPrefix,
) -> Result<Event, Error> {
    Ok(match event_type {
        EventType::Inception => Event {
            prefix: IdentifierPrefix::Basic(identifier),
            sn: sn,
            event_data: EventData::Icp(InceptionEvent {
                key_config: KeyConfig {
                    threshold: 1,
                    public_keys: vec![curr_key],
                    threshold_key_digest: nxt,
                },
                witness_config: InceptionWitnessConfig::default(),
                inception_configuration: vec![],
            }),
        },
        EventType::Rotation => Event {
            prefix: IdentifierPrefix::Basic(identifier),
            sn: sn,
            event_data: EventData::Rot(RotationEvent {
                previous_event_hash: prev_event,
                key_config: KeyConfig {
                    threshold: 1,
                    public_keys: vec![curr_key],
                    threshold_key_digest: nxt,
                },
                witness_config: WitnessConfig::default(),
            }),
        },
    })
}

/// Collects data for testing `IdentifierState` update.
/// `prev_event_hash`, `sn` and `keypair` are used to generate mock event message
/// of given type,
/// `history_prefs` are used to check if any keypair used earlier
/// in event message sequence can verify current message.
pub struct TestStateData {
    state: IdentifierState,
    history_prefs: Vec<BasicPrefix>,
    prev_event_hash: SelfAddressingPrefix,
    sn: u64,
    keypair: (PublicKey, PrivateKey),
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
        history_prefs: vec![],
        prev_event_hash: SelfAddressingPrefix::default(),
        sn: 0,
        keypair: keypair,
    })
}

/// Construct mock event message from `event_type` and `state_data`, apply it to
/// `IdentifierState` in `state_data.state` and check if it was updated correctly.
fn test_update_identifier_state(
    event_type: EventType,
    state_data: TestStateData,
) -> Result<TestStateData, Error> {
    // Get current key_pair from argument.
    let (cur_pk, cur_sk) = state_data.keypair;
    let current_pref = Basic::Ed25519.derive(cur_pk);
    // If `history_prefs` isn't empty, set its first prefix, as identifier prefix.
    // Otherwise set current_prefix as identifier prefix. (It's inception event).
    let identifier = match state_data.history_prefs.first() {
        Some(bp) => bp.clone(),
        None => current_pref.clone(),
    };

    // Generate ed25519 next (ensuing) keypair and hash it.
    let ed = ed25519::Ed25519Sha512::new();
    let (next_pk, next_sk) = ed
        .keypair(Option::None)
        .map_err(|e| Error::CryptoError(e))?;

    let next_prefix = Basic::Ed25519.derive(next_pk.clone());
    let next_dig = SelfAddressing::Blake3_256.derive(next_prefix.to_str().as_bytes());

    // Generate mock event msg of given type.
    let event_msg = {
        let event = create_mock_event(
            event_type,
            state_data.sn,
            state_data.prev_event_hash.clone(),
            identifier.clone(),
            current_pref.clone(),
            next_dig.clone(),
        );
        event?.to_message(&SerializationFormats::JSON)
    }?;

    // Serialise event message before signing.
    let sed = event_msg.serialize()?;

    let attached_sig = {
        // Sign.
        let sig = ed.sign(&sed, &cur_sk).map_err(|e| Error::CryptoError(e))?;
        AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, sig, 0)
    };

    // Attach sign to event message.
    let signed_event = event_msg.sign(vec![attached_sig.clone()]);

    // Apply event to current IdentifierState.
    let new_state = state_data.state.verify_and_apply(&signed_event)?;

    // Check if current prefix can verify message and signature.
    assert!(current_pref.verify(&sed, &attached_sig.signature)?);

    // Check if any of previous prefixes can verify message and signature.
    for old_pref in state_data.history_prefs.clone() {
        assert!(old_pref.verify(&sed, &attached_sig.signature).is_err())
    }
    // Check if state is updated correctly.
    assert_eq!(new_state.prefix, IdentifierPrefix::Basic(identifier));
    assert_eq!(new_state.sn, state_data.sn);
    assert_eq!(new_state.last, signed_event.serialize()?);
    assert_eq!(new_state.current.signers.len(), 1);
    assert_eq!(new_state.current.signers[0], current_pref);
    assert_eq!(new_state.current.threshold, 1);
    assert_eq!(new_state.next, next_dig);
    assert_eq!(new_state.witnesses, vec![]);
    assert_eq!(new_state.tally, 0);
    assert_eq!(new_state.delegated_keys, vec![]);

    // Append current prefix to prefixes history. It will be obsolete in the future establishement events.
    let mut new_history = state_data.history_prefs.clone();
    new_history.push(current_pref);
    // Current event will be previous event for the next one, so return its hash.
    let prev_event_hash = SelfAddressing::Blake3_256.derive(&signed_event.serialize()?);
    // Compute sn for next event.
    let next_sn = state_data.sn + 1;

    Ok(TestStateData {
        state: new_state,
        history_prefs: new_history,
        prev_event_hash,
        sn: next_sn,
        keypair: (next_pk, next_sk),
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
