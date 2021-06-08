use crate::{
    event_message::parse::message,
    prefix::{
        AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, SelfAddressingPrefix,
        SelfSigningPrefix,
    },
    state::IdentifierState,
};
#[cfg(feature = "lmdb")]
pub mod lmdb;

#[cfg(feature = "sled-db")]
pub mod sled;
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

    /// Get KERL for Prefix
    ///
    /// Returns the current validated KERL for a given Prefix
    fn get_kerl(&self, id: &IdentifierPrefix) -> Result<Option<Vec<u8>>, Self::Error>;

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
        signer: &BasicPrefix,
        sig: &SelfSigningPrefix,
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

    /// Escrow Non-Transferrable Receipt
    fn escrow_nt_receipt(
        &self,
        pref: &IdentifierPrefix,
        dig: &SelfAddressingPrefix,
        signer: &BasicPrefix,
        sig: &SelfSigningPrefix,
    ) -> Result<(), Self::Error>;

    /// Escrow Transferrable Receipt
    fn escrow_t_receipt(
        &self,
        pref: &IdentifierPrefix,
        dig: &SelfAddressingPrefix,
        signer: &IdentifierPrefix,
        sig: &AttachedSignaturePrefix,
    ) -> Result<(), Self::Error>;

    fn has_receipt(
        &self,
        pref: &IdentifierPrefix,
        sn: u64,
        validator: &IdentifierPrefix,
    ) -> Result<bool, Self::Error>;
}

#[cfg(test)]
pub(crate) fn test_db<D: EventDatabase>(db: D) -> Result<(), D::Error> {
    use crate::{
        derivation::self_addressing::SelfAddressing,
        event_message::parse::{signed_message, Deserialized},
    };

    // NOTE this is not actually a valid kel (sig indexes and prefix are wrong), just has the correct form
    let signed = br#"{"v":"KERI10JSON000144_","i":"E005TfcIFvrzhJFxoGqebPHvtanxEwcfJOAYcUtCmhk8","s":"0","t":"icp","kt":"1","k":["D5UzOMC5Knhi5eA-Cr8ASuD8lUcZMcLtAhIZ33W5Z4hs","DEbposribdTgsnCSQgmVN6VKoc4Vpc-hs9rbskXQ2O2M","D46n6npISQETk7eGYnwe5Jq7USmEsckHeJRu2YoTCXhU"],"n":"E2zBfVYkE2uaGR5DmMVBbWsIdBIZVu5Ml6joenraD5Ho","bt":"0","b":[],"c":[],"a":[]}-AADAAKfgMIEsKlrXqUxUyw1Qq7gFrg9mNWcDAkQAXUW6Hppvt4NBdEbU_2Wy7Re0zp5zVvLjjq4hjPE5aXSeIlHh7DgABIkKK8jI0l_tor7EaIM2B65aLn9e6Y3Igwa9OjDqbiyqXdL1yHxga7nhJY80Ct0zXGhm7hgLzgB6d86EqfXWLCQACBPCeqK_WXY64EZ8E91Y2trI6MfZT-f2NmtHCmmKhvt7AmehPcvQSvrcQbogdNEBr749AbVG7glVsV8WitVR2DQ"#;
    let deser = match signed_message(signed).unwrap().1 {
        Deserialized::Event(e) => e,
        _ => panic!(),
    };

    let dig = SelfAddressing::Blake3_256.derive(deser.event.raw);

    db.log_event(
        &deser.event.event.event.prefix,
        &dig,
        deser.event.raw,
        &deser.signatures,
    )?;

    db.finalise_event(&deser.event.event.event.prefix, 0, &dig)?;

    let written = db.last_event_at_sn(&deser.event.event.event.prefix, 0)?;

    assert_eq!(written, Some(deser.event.raw.to_vec()));

    let kerl = db.get_kerl(&deser.event.event.event.prefix)?.unwrap();
    let deser_2 = match signed_message(&kerl).unwrap().1 {
        Deserialized::Event(e) => e,
        _ => panic!(),
    };

    assert_eq!(deser, deser_2);

    Ok(())
}
