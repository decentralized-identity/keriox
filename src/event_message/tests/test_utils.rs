use ursa::{
    keys::{PrivateKey, PublicKey},
    signatures::{ed25519, SignatureScheme},
};

use crate::{
    derivation::{basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning},
    error::Error,
    event::event_data::{
        inception::InceptionEvent, interaction::InteractionEvent, rotation::RotationEvent,
        EventData,
    },
    event::sections::{nxt_commitment, InceptionWitnessConfig, KeyConfig, WitnessConfig},
    event::Event,
    event::SerializationFormats,
    prefix::{
        AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, Prefix, SelfAddressingPrefix,
    },
    state::IdentifierState,
};

#[derive(Clone)]
pub enum EventType {
    Inception,
    Rotation,
    Interaction,
}

impl EventType {
    fn is_establishment_event(&self) -> bool {
        match self {
            EventType::Inception | EventType::Rotation => true,
            _ => false,
        }
    }
}

/// Create mock event on given type. For now only inception, rotation and interaction events.
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
                key_config: KeyConfig::new(vec![curr_key], nxt, Some(1)),
                witness_config: InceptionWitnessConfig::default(),
                inception_configuration: vec![],
            }),
        },
        EventType::Rotation => Event {
            prefix: IdentifierPrefix::Basic(identifier),
            sn: sn,
            event_data: EventData::Rot(RotationEvent {
                previous_event_hash: prev_event,
                key_config: KeyConfig::new(vec![curr_key], nxt, Some(1)),
                witness_config: WitnessConfig::default(),
                data: vec![],
            }),
        },
        EventType::Interaction => Event {
            prefix: IdentifierPrefix::Basic(identifier),
            sn: sn,
            event_data: EventData::Ixn(InteractionEvent {
                previous_event_hash: prev_event,
                data: vec![],
            }),
        },
    })
}

/// Collects data for testing `IdentifierState` update. `prev_event_hash`, `sn`,
/// `current_keypair` and `new_keypair` are used to generate mock event message
/// of given type, `history_prefs` are used to check if any keypair used earlier
/// in event message sequence can verify current message.
pub struct TestStateData {
    state: IdentifierState,
    history_prefs: Vec<BasicPrefix>,
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
        history_prefs: vec![],
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

    let current_pref = Basic::Ed25519.derive(cur_pk.clone());
    let next_prefix = Basic::Ed25519.derive(next_pk.clone());
    let next_dig = nxt_commitment(1, &[next_prefix], SelfAddressing::Blake3_256);

    // If `history_prefs` isn't empty, set its first prefix, as identifier prefix.
    // Otherwise set current_prefix as identifier prefix. (It's inception event).
    let identifier = match state_data.history_prefs.first() {
        Some(bp) => bp.clone(),
        None => current_pref.clone(),
    };

    // Generate mock event msg of given type.
    let event_msg = {
        let event = create_mock_event(
            event_type.clone(),
            state_data.sn,
            state_data.prev_event_hash.clone(),
            identifier.clone(),
            current_pref.clone(),
            next_dig.clone(),
        );
        event?.to_message(SerializationFormats::JSON)
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
    let new_state = state_data.state.apply(&signed_event)?;

    assert!(new_state.current.verify(&sed, &signed_event.signatures)?);

    // Check if current prefix can verify message and signature.
    assert!(current_pref.verify(&sed, &attached_sig.signature)?);

    // If generated event is establishment event, check if any of previous
    // prefixes can verify message and signature.
    if event_type.is_establishment_event() {
        for old_pref in state_data.history_prefs.clone() {
            assert!(old_pref.verify(&sed, &attached_sig.signature).is_err())
        }
    };

    // Check if state is updated correctly.
    assert_eq!(new_state.prefix, IdentifierPrefix::Basic(identifier));
    assert_eq!(new_state.sn, state_data.sn);
    assert_eq!(new_state.last, sed);
    assert_eq!(new_state.current.public_keys.len(), 1);
    assert_eq!(new_state.current.public_keys[0], current_pref);
    assert_eq!(new_state.current.threshold, 1);
    assert_eq!(new_state.current.threshold_key_digest, next_dig);
    assert_eq!(new_state.witnesses, vec![]);
    assert_eq!(new_state.tally, 0);
    assert_eq!(new_state.delegated_keys, vec![]);

    let mut new_history = state_data.history_prefs.clone();
    // If event_type is establishment event, append current prefix to prefixes
    // history. It will be obsolete in the future establishement events.
    if event_type.is_establishment_event() {
        new_history.push(current_pref);
    }
    // Current event will be previous event for the next one, so return its hash.
    let prev_event_hash = SelfAddressing::Blake3_256.derive(&sed);
    // Compute sn for next event.
    let next_sn = state_data.sn + 1;

    Ok(TestStateData {
        state: new_state,
        history_prefs: new_history,
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
