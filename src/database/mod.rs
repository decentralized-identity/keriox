use crate::prefix::{AttachedSignaturePrefix, IdentifierPrefix, SelfAddressingPrefix};
use chrono::prelude::*;

pub trait MapTable<K, V> {
    type Error;

    /// Put
    ///
    /// Adds the given value at the given key, IF there is no existing value for that key
    /// Returns true if insertion succeeds, false otherwise
    fn put(&self, key: &K, value: V) -> Result<(), Self::Error>;

    /// Set
    ///
    /// Sets the given key to the given value, OVERWRITES the existing value if there is one
    fn set(&self, key: &K, value: V) -> Result<(), Self::Error>;

    /// Get
    ///
    /// Returns the value associated with the given key
    fn get(&self, key: &K) -> Result<Option<V>, Self::Error>;

    /// Delete
    ///
    /// Removes all values for the given key
    fn del(&self, key: &K) -> Result<(), Self::Error>;
}

pub trait MultiMapTable<K, V> {
    type Error;

    /// Put
    ///
    /// Adds the given value at the given key, IF there is no existing value for that key
    /// Returns true if insertion succeeds, false otherwise
    fn put(&self, key: &K, value: V) -> Result<(), Self::Error>;

    /// Set
    ///
    /// Sets the given key to the given value, OVERWRITES the existing value if there is one
    fn set(&self, key: &K, value: V) -> Result<(), Self::Error>;

    /// Get
    ///
    /// Returns the value associated with the given key
    fn get(&self, key: &K) -> Result<Option<Vec<V>>, Self::Error>;

    /// Delete
    ///
    /// Removes all values for the given key
    fn del(&self, key: &K) -> Result<(), Self::Error>;

    /// Count
    ///
    /// Returns the number of items for the given key
    fn cnt(&self, key: &K) -> Result<Option<usize>, Self::Error> {
        Ok(self.get(key)?.map(|v| v.len()))
    }

    /// Iterate
    ///
    /// Returns an iterator over the items for the given key
    fn itr(&self, key: &K) -> Result<Option<Box<dyn Iterator<Item = V>>>, Self::Error>;
}

pub trait EventDatabase<Evts, Dtss, Sigs, Rcts, Ures, Kels, Pses, Ooes, Dels, Ldes>
where
    Evts: MapTable<(IdentifierPrefix, SelfAddressingPrefix), Vec<u8>>,
    Dtss: MapTable<(IdentifierPrefix, SelfAddressingPrefix), DateTime<Utc>>,
    Sigs: MultiMapTable<(IdentifierPrefix, SelfAddressingPrefix), AttachedSignaturePrefix>,
    Rcts: MultiMapTable<(IdentifierPrefix, SelfAddressingPrefix), String>,
    Ures: MapTable<(IdentifierPrefix, SelfAddressingPrefix), String>,
    Kels: MultiMapTable<(IdentifierPrefix, u32), SelfAddressingPrefix>,
    Pses: MultiMapTable<(IdentifierPrefix, u32), SelfAddressingPrefix>,
    Ooes: MultiMapTable<(IdentifierPrefix, u32), SelfAddressingPrefix>,
    Dels: MultiMapTable<(IdentifierPrefix, u32), SelfAddressingPrefix>,
    Ldes: MultiMapTable<(IdentifierPrefix, u32), SelfAddressingPrefix>,
{
    /// Events, serialized
    ///
    /// Keys: ID prefix + digest of serialized event
    /// Values: serialized event bytes
    fn evts(&self) -> &Evts;

    /// Datetime Stamps
    ///
    /// Keys: ID prefix + digest of serialized event
    /// Values: ISO 8601 datetime strings, first occurance of given event
    fn dtss(&self) -> &Dtss;

    /// Signatures
    ///
    /// Keys: ID prefix + digest of serialized event
    /// Values: event signatures, >1 per key is allowed
    fn sigs(&self) -> &Sigs;

    /// Receipt Couplets
    ///
    /// Keys: ID prefix + digest of serialized event
    /// Values: Witness/Validator ID prefix + event signature, >1 per key is allowed
    fn rcts(&self) -> &Rcts;

    /// Unverified Receipt Couplet
    ///
    /// Keys: Witness/Validator ID prefix + digest of serialized event
    /// Values: event ID prefix + event signature (?)
    fn ures(&self) -> &Ures;

    /// Key Event Digest List
    ///
    /// Keys: ID Prefix + sn of key event
    /// Values: digest of events, for lookup in evts, >1 per key is allowed
    fn kels(&self) -> &Kels;

    /// Partial Signed Escrow Events
    ///
    /// Keys: ID Prefix + sn of key event
    /// Values: digest of events, for lookup in evts, >1 per key is allowed
    fn pses(&self) -> &Pses;

    /// Out of Order Escrow Event digest
    ///
    /// Keys: ID Prefix + sn of key event
    /// Values: digest of events, for lookup in evts, >1 per key is allowed
    fn ooes(&self) -> &Ooes;

    /// Duplicitous Event Entry Digest
    ///
    /// Keys: ID Prefix + sn of key event
    /// Values: digest of events, for lookup in evts, >1 per key is allowed
    fn dels(&self) -> &Dels;

    /// Likely Duplicitous Escrow Events
    ///
    /// Keys: ID Prefix + sn of key event
    /// Values: digest of events, for lookup in evts, >1 per key is allowed
    fn ldes(&self) -> &Ldes;
}

#[test]
fn test() {}
