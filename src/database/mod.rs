pub trait MapTable<K, V> {
    /// Put
    ///
    /// Adds the given value at the given key, IF there is no existing value for that key
    /// Returns true if insertion succeeds, false otherwise
    fn put(&self, key: &K, value: V) -> bool;

    /// Set
    ///
    /// Sets the given key to the given value, OVERWRITES the existing value if there is one
    fn set(&self, key: &K, value: V) -> bool;

    /// Get
    ///
    /// Returns the value associated with the given key
    fn get(&self, key: &K) -> V;

    /// Delete
    ///
    /// Removes all values for the given key
    fn del(&self, key: &K) -> bool;
}

pub trait MultiMapTable<K, V> {
    /// Put
    ///
    /// Adds the given value at the given key, IF there is no existing value for that key
    /// Returns true if insertion succeeds, false otherwise
    fn put(&self, key: &K, value: V) -> bool;

    /// Set
    ///
    /// Sets the given key to the given value, OVERWRITES the existing value if there is one
    fn set(&self, key: &K, value: V) -> bool;

    /// Get
    ///
    /// Returns the value associated with the given key
    fn get(&self, key: &K) -> Box<dyn AsRef<&[V]>> {
        self.itr(key).collect()
    }

    /// Delete
    ///
    /// Removes all values for the given key
    fn del(&self, key: &K) -> bool;

    /// Count
    ///
    /// Returns the number of items for the given key
    fn cnt(&self, key: &K) -> usize {
        self.get(key).len()
    }

    /// Iterate
    ///
    /// Returns an iterator over the items for the given key
    fn itr(&self, key: &K) -> Box<dyn Iterator<Item = V>>;
}

pub trait EventDatabase<Evts, Dtss, Sigs, Rcts, Ures, Kels, Pses, Ooes, Dels, Ldes>
where
    Evts: MapTable<String, Vec<u8>>,
    Dtss: MapTable<String, String>,
    Sigs: MultiMapTable<String, String>,
    Rcts: MultiMapTable<String, String>,
    Ures: MapTable<String, String>,
    Kels: MultiMapTable<String, String>,
    Pses: MultiMapTable<String, String>,
    Ooes: MultiMapTable<String, String>,
    Dels: MultiMapTable<String, String>,
    Ldes: MultiMapTable<String, String>,
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
    fn ooes(&self) -> &Ooes;

    /// Duplicitous Event Entry Digest
    fn dels(&self) -> &Dels;

    /// Likely Duplicitous Escrow Events
    fn ldes(&self) -> &Ldes;
}

#[test]
fn test() {}
