use aya::{
    maps::{
        lpm_trie::{Key, LpmTrie},
        MapData, MapError,
    },
    Pod,
};

pub trait BpfStore<K: Pod, V: Pod> {
    fn insert(&mut self, key: &Key<K>, value: V) -> Result<(), MapError>;
    fn remove(&mut self, key: &Key<K>) -> Result<(), MapError>;
}

impl<T: AsMut<MapData>, K: Pod, V: Pod> BpfStore<K, V> for LpmTrie<T, K, V> {
    fn insert(&mut self, key: &Key<K>, value: V) -> Result<(), MapError> {
        LpmTrie::insert(self, key, value, 0)
    }

    fn remove(&mut self, key: &Key<K>) -> Result<(), MapError> {
        LpmTrie::remove(self, key)
    }
}
