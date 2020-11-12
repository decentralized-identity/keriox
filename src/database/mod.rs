use crate::prefix::{AttachedSignaturePrefix, IdentifierPrefix, SelfAddressingPrefix};
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
    use crate::{
        derivation::self_addressing::SelfAddressing, event::event_data::EventData,
        event_message::parse::message,
    };

    let raw = r#"{"vs":"KERI10JSON000159_","pre":"ECui-E44CqN2U7uffCikRCp_YKLkPrA4jsTZ_A0XRLzc","sn":"0","ilk":"icp","sith":"2","keys":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"nxt":"Evhf3437ZRRnVhT0zOxo_rBX_GxpGoAnLuzrVlDK8ZdM","toad":"0","wits":[],"cnfg":[]}extra data"#;
    let sigs: Vec<AttachedSignaturePrefix> = [
        "AAJ66nrRaNjltE31FZ4mELVGUMc_XOqOAOXZQjZCEAvbeJQ8r3AnccIe1aepMwgoQUeFdIIQLeEDcH8veLdud_DQ",
        "ABTQYtYWKh3ScYij7MOZz3oA6ZXdIDLRrv0ObeSb4oc6LYrR1LfkICfXiYDnp90tAdvaJX5siCLjSD3vfEM9ADDA",
        "ACQTgUl4zF6U8hfDy8wwUva-HCAiS8LQuP7elKAHqgS8qtqv5hEj3aTjwE91UtgAX2oCgaw98BCYSeT5AuY1SpDA",
    ]
    .iter()
    .map(|raw| raw.parse().unwrap())
    .collect();

    let event = message(raw).unwrap().1.event;
    let dig = SelfAddressing::Blake3_256.derive(raw.as_bytes());

    db.log_event(&event.prefix, &dig, raw.as_bytes(), &sigs)?;
    db.finalise_event(&event.prefix, 0, &dig)?;

    let written = db.last_event_at_sn(&event.prefix, 0)?;

    assert_eq!(written, Some(raw.as_bytes().to_vec()));
    Ok(())
}
