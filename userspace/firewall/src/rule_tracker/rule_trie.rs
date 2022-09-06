use std::ops::Deref;

use aya::{
    maps::{
        lpm_trie::{Key, LpmTrie},
        Map, MapError,
    },
    Pod,
};

pub trait RuleTrie<K: Pod, V: Pod> {
    fn insert(&mut self, key: &Key<K>, value: V) -> Result<(), MapError>;
    fn remove(&mut self, key: &Key<K>) -> Result<(), MapError>;
}

impl<T: Deref<Target = Map>, K: Pod, V: Pod> RuleTrie<K, V> for LpmTrie<T, K, V> {
    fn insert(&mut self, key: &Key<K>, value: V) -> Result<(), MapError> {
        LpmTrie::insert(self, key, value, 0)
    }

    fn remove(&mut self, key: &Key<K>) -> Result<(), MapError> {
        LpmTrie::remove(self, key)
    }
}
