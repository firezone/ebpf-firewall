use aya::{
    maps::{
        lpm_trie::{Key, LpmTrie},
        HashMap, MapData, MapError,
    },
    Pod,
};

pub trait BpfStore {
    type K;
    type V;
    fn insert(&mut self, key: &Self::K, value: Self::V) -> Result<(), MapError>;
    fn get(&self, key: &Self::K) -> Result<Self::V, MapError>;
    fn remove(&mut self, key: &Self::K) -> Result<(), MapError>;
}

impl<T: AsMut<MapData> + AsRef<MapData>, K: Pod, V: Pod> BpfStore for LpmTrie<T, K, V> {
    type K = Key<K>;
    type V = V;
    fn insert(&mut self, key: &Self::K, value: Self::V) -> Result<(), MapError> {
        LpmTrie::insert(self, key, value, 0)
    }

    fn remove(&mut self, key: &Self::K) -> Result<(), MapError> {
        LpmTrie::remove(self, key)
    }

    fn get(&self, key: &Self::K) -> Result<Self::V, MapError> {
        LpmTrie::get(self, key, 0)
    }
}

impl<T: AsMut<MapData> + AsRef<MapData>, K: Pod, V: Pod> BpfStore for HashMap<T, K, V> {
    type K = K;
    type V = V;
    fn insert(&mut self, key: &Self::K, value: Self::V) -> Result<(), MapError> {
        HashMap::insert(self, key, value, 0)
    }

    fn remove(&mut self, key: &Self::K) -> Result<(), MapError> {
        HashMap::remove(self, key)
    }

    fn get(&self, key: &Self::K) -> Result<Self::V, MapError> {
        HashMap::get(self, key, 0)
    }
}
