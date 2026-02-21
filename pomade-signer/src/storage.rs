use std::marker::PhantomData;
use std::path::Path;

use serde::{Serialize, de::DeserializeOwned};

pub struct Collection<T> {
    tree: sled::Tree,
    _marker: PhantomData<T>,
}

impl<T> Collection<T>
where
    T: Serialize + DeserializeOwned,
{
    pub fn get(&self, key: &str) -> Option<T> {
        self.tree
            .get(key)
            .ok()
            .flatten()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    }

    pub fn set(&self, key: &str, value: &T) {
        if let Ok(bytes) = serde_json::to_vec(value) {
            let _ = self.tree.insert(key, bytes);
        }
    }

    pub fn delete(&self, key: &str) -> bool {
        self.tree.remove(key).ok().flatten().is_some()
    }

    pub fn entries(&self) -> Vec<(String, T)> {
        self.tree
            .iter()
            .filter_map(|r| r.ok())
            .filter_map(|(k, v)| {
                let key = String::from_utf8(k.to_vec()).ok()?;
                let value = serde_json::from_slice(&v).ok()?;
                Some((key, value))
            })
            .collect()
    }
}

pub struct Storage {
    db: sled::Db,
}

impl Storage {
    pub fn open(path: impl AsRef<Path>) -> sled::Result<Self> {
        Ok(Self {
            db: sled::open(path)?,
        })
    }

    pub fn collection<T>(&self, name: &str) -> sled::Result<Collection<T>> {
        Ok(Collection {
            tree: self.db.open_tree(name)?,
            _marker: PhantomData,
        })
    }
}
