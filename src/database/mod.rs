use crate::prefix::{AttachedSignaturePrefix, IdentifierPrefix, SelfAddressingPrefix};

pub trait EventDatabase<'a> {
    type Error;
    /// Last Event At SN
    ///
    /// Returns the raw bytes of the last event inserted
    /// for a given identifier at a given sequence number
    /// (rotation events can supercede interaction events
    /// with the same sn)
    fn last_event_at_sn(&self, pref: &IdentifierPrefix, sn: u64) -> Option<&'a [u8]>;

    /// Log Event
    ///
    /// Adds the raw event data to the database
    /// Should also log the time
    fn log_event(
        &self,
        raw: &[u8],
        prefix: &IdentifierPrefix,
        dig: &SelfAddressingPrefix,
        sigs: &[AttachedSignaturePrefix],
    ) -> Result<(), Self::Error>;

    /// Commit Event
    ///
    /// Update associated logs for fully verified event
    fn commit_event(
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

    /// Add Receipt
    ///
    /// Associates a signature Sig made by Signer with the event referenced by Dig and Pref
    fn add_receipt(
        &self,
        pref: &IdentifierPrefix,
        dig: &SelfAddressingPrefix,
        signer: &IdentifierPrefix,
        sig: &AttachedSignaturePrefix,
    ) -> Result<(), Self::Error>;
}
