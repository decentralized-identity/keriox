use crate::prefix::{
    AttachedSignaturePrefix, IdentifierPrefix, Prefix, SelfAddressingPrefix, SelfSigningPrefix,
};
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

pub struct ContentIndex(IdentifierPrefix, SelfAddressingPrefix);
pub struct SequenceIndex(IdentifierPrefix, u32);

// useful for using as an index type, but expensive
// TODO: investigate using AsRef<[u8]>
impl From<ContentIndex> for Vec<u8> {
    fn from(ci: ContentIndex) -> Self {
        [ci.0.to_str(), ci.1.to_str()].concat().into_bytes()
    }
}

impl From<SequenceIndex> for Vec<u8> {
    fn from(si: SequenceIndex) -> Self {
        format!("{}.{:032x}", si.0.to_str(), si.1).into_bytes()
    }
}

pub trait EventDatabase<Evts, Dtss, Sigs, Rcts, Ures, Vrcs, Vres, Kels, Pses, Ooes, Dels, Ldes>
where
    Evts: MapTable<ContentIndex, Vec<u8>>,
    Dtss: MapTable<ContentIndex, DateTime<Utc>>,
    Sigs: MultiMapTable<ContentIndex, AttachedSignaturePrefix>,
    Rcts: MultiMapTable<ContentIndex, (IdentifierPrefix, SelfSigningPrefix)>,
    Ures: MapTable<ContentIndex, (IdentifierPrefix, SelfSigningPrefix)>,
    Vrcs: MultiMapTable<
        ContentIndex,
        (
            IdentifierPrefix,
            SelfAddressingPrefix,
            AttachedSignaturePrefix,
        ),
    >,
    Vres: MultiMapTable<
        ContentIndex,
        (
            IdentifierPrefix,
            SelfAddressingPrefix,
            AttachedSignaturePrefix,
        ),
    >,
    Kels: MultiMapTable<SequenceIndex, SelfAddressingPrefix>,
    Pses: MultiMapTable<SequenceIndex, SelfAddressingPrefix>,
    Ooes: MultiMapTable<SequenceIndex, SelfAddressingPrefix>,
    Dels: MultiMapTable<SequenceIndex, SelfAddressingPrefix>,
    Ldes: MultiMapTable<SequenceIndex, SelfAddressingPrefix>,
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

    /// Receipt Couplets (non-transferable)
    ///
    /// Keys: ID prefix + digest of serialized event
    /// Values: Witness/Validator ID prefix + event signature, >1 per key is allowed
    fn rcts(&self) -> &Rcts;

    /// Unverified Receipt Couplet (non-transferable)
    ///
    /// Keys: ID prefix + digest of serialized event
    /// Values: Witness/Validator ID prefix + event signature (?)
    fn ures(&self) -> &Ures;

    /// Receipt triplets (transferable)
    ///
    /// Keys: ID prefix + digest of serialized event
    /// Values: Witness/Validator ID prefix + latest witness/validator establishment event digest + event signature
    fn vrcs(&self) -> &Vrcs;

    /// Unverified Receipt triplets (transferable)
    ///
    /// Keys: Witness/Validator ID prefix + digest of serialized event
    /// Values: Witness/Validator ID prefix + latest witness/validator establishment event digest + event signature
    fn vres(&self) -> &Vres;

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
