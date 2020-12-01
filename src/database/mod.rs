use crate::{
    event_message::parse::message,
    prefix::{AttachedSignaturePrefix, IdentifierPrefix, SelfAddressingPrefix},
    state::IdentifierState,
};
#[cfg(feature = "lmdb")]
pub mod lmdb;

/// Event Database
///
/// An Abstract model of state for Key Events,
/// Signatures and Receipts.
pub trait EventDatabase {
    type Error;
    /// Last Event At SN
    ///
    /// Returns the raw bytes of the last event inserted
    /// for a given identifier at a given sequence number
    /// (rotation events can supercede interaction events
    /// with the same sn)
    /// TODO: see if it can return a Result<Option<&'a [u8]>_>
    fn last_event_at_sn(
        &self,
        pref: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Get State for Prefix
    ///
    /// Returns the current State associated with
    /// the given Prefix
    fn get_state_for_prefix(
        &self,
        pref: &IdentifierPrefix,
    ) -> Result<Option<IdentifierState>, Self::Error> {
        // start with empty state
        let mut state = IdentifierState::default();

        // starting from inception
        for sn in 0.. {
            // read the latest raw event
            let raw = match self.last_event_at_sn(pref, sn)? {
                Some(r) => r,
                None => {
                    if sn == 0 {
                        // no inception event, no state
                        return Ok(None);
                    } else {
                        // end of KEL, stop looping
                        break;
                    }
                }
            };
            // parse event
            // FIXME, DONT UNWRAP
            let parsed = message(&raw).unwrap().1;
            // apply it to the state
            // TODO avoid .clone()
            state = match state.clone().apply(&parsed.event) {
                Ok(s) => s,
                // will happen when a recovery has overridden some part of the KEL,
                // stop processing here
                Err(_) => break,
            }
        }

        Ok(Some(state))
    }

    /// Get Children of Prefix
    ///
    /// Returns the Identifiers delegated to by the
    /// given Prefix
    fn get_children_of_prefix(
        &self,
        _pref: &IdentifierPrefix,
    ) -> Result<Option<Vec<IdentifierPrefix>>, Self::Error> {
        todo!()
    }

    /// Get Parent of Prefix
    ///
    /// Returns the delegator for the given Prefix,
    /// if there is one
    fn get_parent_of_prefix(
        &self,
        _pref: &IdentifierPrefix,
    ) -> Result<Option<IdentifierPrefix>, Self::Error> {
        todo!()
    }

    /// Log Event
    ///
    /// Adds the raw event data to the database and a timestamp
    fn log_event(
        &self,
        prefix: &IdentifierPrefix,
        dig: &SelfAddressingPrefix,
        raw: &[u8],
        sigs: &[AttachedSignaturePrefix],
    ) -> Result<(), Self::Error>;

    /// Finalise Event
    ///
    /// Update associated logs for fully verified event
    fn finalise_event(
        &self,
        prefix: &IdentifierPrefix,
        sn: u64,
        dig: &SelfAddressingPrefix,
    ) -> Result<(), Self::Error>;

    /// Escrow Partially Signed Event
    ///
    /// Escrows an Event which does not have enough signatures
    fn escrow_partially_signed_event(
        &self,
        pref: &IdentifierPrefix,
        sn: u64,
        dig: &SelfAddressingPrefix,
    ) -> Result<(), Self::Error>;

    /// Escrow Out of Order Event
    ///
    /// Escrows an Event which has arrived before previous events
    fn escrow_out_of_order_event(
        &self,
        pref: &IdentifierPrefix,
        sn: u64,
        dig: &SelfAddressingPrefix,
    ) -> Result<(), Self::Error>;

    /// Likely Duplicitous Event
    ///
    /// Marks an event as being likely duplicitous
    fn likely_duplicitous_event(
        &self,
        pref: &IdentifierPrefix,
        sn: u64,
        dig: &SelfAddressingPrefix,
    ) -> Result<(), Self::Error>;

    /// Duplicitous Event
    ///
    /// Marks an event as being known duplicitous
    fn duplicitous_event(
        &self,
        pref: &IdentifierPrefix,
        sn: u64,
        dig: &SelfAddressingPrefix,
    ) -> Result<(), Self::Error>;

    /// Add Non-Transferrable Receipt
    ///
    /// Associates a signature Sig made by Signer with the event referenced by Dig and Pref
    fn add_nt_receipt_for_event(
        &self,
        pref: &IdentifierPrefix,
        dig: &SelfAddressingPrefix,
        signer: &IdentifierPrefix,
        sig: &AttachedSignaturePrefix,
    ) -> Result<(), Self::Error>;

    /// Add Transferrable Receipt
    ///
    /// Associates a signature Sig made by Signer with the event referenced by Dig and Pref
    fn add_t_receipt_for_event(
        &self,
        pref: &IdentifierPrefix,
        dig: &SelfAddressingPrefix,
        signer: &IdentifierPrefix,
        sig: &AttachedSignaturePrefix,
    ) -> Result<(), Self::Error>;
}

pub(crate) fn test_db<D: EventDatabase>(db: D) -> Result<(), D::Error> {
    use crate::{derivation::self_addressing::SelfAddressing, event::event_data::EventData};

    let raw = r#"{"vs":"KERI10JSON000159_","pre":"ECui-E44CqN2U7uffCikRCp_YKLkPrA4jsTZ_A0XRLzc","sn":"0","ilk":"icp","sith":"2","keys":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"nxt":"Evhf3437ZRRnVhT0zOxo_rBX_GxpGoAnLuzrVlDK8ZdM","toad":"0","wits":[],"cnfg":[]}extra data"#;
    let sigs: Vec<AttachedSignaturePrefix> = [
        "AAJ66nrRaNjltE31FZ4mELVGUMc_XOqOAOXZQjZCEAvbeJQ8r3AnccIe1aepMwgoQUeFdIIQLeEDcH8veLdud_DQ",
        "ABTQYtYWKh3ScYij7MOZz3oA6ZXdIDLRrv0ObeSb4oc6LYrR1LfkICfXiYDnp90tAdvaJX5siCLjSD3vfEM9ADDA",
        "ACQTgUl4zF6U8hfDy8wwUva-HCAiS8LQuP7elKAHqgS8qtqv5hEj3aTjwE91UtgAX2oCgaw98BCYSeT5AuY1SpDA",
    ]
    .iter()
    .map(|raw| raw.parse().unwrap())
    .collect();

    let event = message(raw.as_bytes()).unwrap().1.event.event;
    let dig = SelfAddressing::Blake3_256.derive(raw.as_bytes());

    db.log_event(&event.prefix, &dig, raw.as_bytes(), &sigs)?;
    db.finalise_event(&event.prefix, 0, &dig)?;

    let written = db.last_event_at_sn(&event.prefix, 0)?;

    assert_eq!(written, Some(raw.as_bytes().to_vec()));

    let state = db.get_state_for_prefix(&event.prefix)?.unwrap();

    assert_eq!(&state.prefix, &event.prefix);
    assert!(match event.event_data {
        EventData::Icp(icp) => icp.key_config == state.current,
        _ => false,
    });

    Ok(())
}
