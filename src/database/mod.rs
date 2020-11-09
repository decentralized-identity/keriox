use crate::{
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
    ) -> Result<Option<IdentifierState>, Self::Error>;

    /// Get Children of Prefix
    ///
    /// Returns the Identifiers delegated to by the
    /// given Prefix
    fn get_children_of_prefix(
        &self,
        pref: &IdentifierPrefix,
    ) -> Result<Option<Vec<IdentifierPrefix>>, Self::Error>;

    /// Get Parent of Prefix
    ///
    /// Returns the delegator for the given Prefix,
    /// if there is one
    fn get_parent_of_prefix(
        &self,
        pref: &IdentifierPrefix,
    ) -> Result<Option<IdentifierPrefix>, Self::Error>;

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
