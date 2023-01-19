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

#[cfg(test)]
pub(crate) mod test_store {
    use std::{collections::HashMap, hash::Hash, marker::PhantomData};

    use aya::{maps::MapError, Pod};

    use super::BpfStore;

    #[derive(Debug)]
    pub(crate) struct TestStore<K, V> {
        _phantom: PhantomData<(K, V)>,
    }

    impl<K, V> TestStore<K, V> {
        pub(crate) fn new() -> Self {
            Self {
                _phantom: PhantomData {},
            }
        }
    }

    impl<K: Pod, V: Pod + Default> BpfStore for TestStore<K, V> {
        type K = K;

        type V = V;

        fn insert(
            &mut self,
            _: &Self::K,
            _: Self::V,
        ) -> std::result::Result<(), aya::maps::MapError> {
            Ok(())
        }

        fn get(&self, _: &Self::K) -> std::result::Result<Self::V, aya::maps::MapError> {
            Ok(V::default())
        }

        fn remove(&mut self, _: &Self::K) -> std::result::Result<(), aya::maps::MapError> {
            Ok(())
        }
    }

    #[derive(Debug)]
    pub(crate) struct HashTestStore<K, V> {
        inner: HashMap<K, V>,
    }

    impl<K, V> HashTestStore<K, V> {
        pub(crate) fn new() -> Self {
            Self {
                inner: Default::default(),
            }
        }
    }

    impl<K: Pod + Eq + Hash, V: Pod + Default> BpfStore for HashTestStore<K, V> {
        type K = K;

        type V = V;

        fn insert(
            &mut self,
            k: &Self::K,
            v: Self::V,
        ) -> std::result::Result<(), aya::maps::MapError> {
            self.inner.insert(k.clone(), v);
            Ok(())
        }

        fn get(&self, k: &Self::K) -> std::result::Result<Self::V, aya::maps::MapError> {
            self.inner.get(k).cloned().ok_or(MapError::ElementNotFound)
        }

        fn remove(&mut self, k: &Self::K) -> std::result::Result<(), aya::maps::MapError> {
            self.inner.remove(k);
            Ok(())
        }
    }
}
