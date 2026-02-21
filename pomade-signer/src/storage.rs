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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use tempfile::TempDir;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestItem {
        id: u32,
        name: String,
        values: Vec<u64>,
    }

    fn create_test_storage() -> (Storage, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::open(&temp_dir.path().join("test.db")).unwrap();
        (storage, temp_dir)
    }

    #[test]
    fn test_storage_open() {
        let (storage, _temp) = create_test_storage();
        // Just verify it opens without error
        drop(storage);
    }

    #[test]
    fn test_collection_get_set() {
        let (storage, _temp) = create_test_storage();
        let collection: Collection<TestItem> = storage.collection("test").unwrap();

        let item = TestItem {
            id: 1,
            name: "test".to_string(),
            values: vec![1, 2, 3],
        };

        // Initially not present
        assert!(collection.get("key1").is_none());

        // Set and retrieve
        collection.set("key1", &item);
        let retrieved = collection.get("key1");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), item);
    }

    #[test]
    fn test_collection_delete() {
        let (storage, _temp) = create_test_storage();
        let collection: Collection<TestItem> = storage.collection("test").unwrap();

        let item = TestItem {
            id: 1,
            name: "test".to_string(),
            values: vec![],
        };

        collection.set("key1", &item);
        assert!(collection.get("key1").is_some());

        // Delete returns true when item existed
        assert!(collection.delete("key1"));
        assert!(collection.get("key1").is_none());

        // Delete returns false when item didn't exist
        assert!(!collection.delete("nonexistent"));
    }

    #[test]
    fn test_collection_entries() {
        let (storage, _temp) = create_test_storage();
        let collection: Collection<TestItem> = storage.collection("test").unwrap();

        let items = vec![
            (
                "key1",
                TestItem {
                    id: 1,
                    name: "one".to_string(),
                    values: vec![1],
                },
            ),
            (
                "key2",
                TestItem {
                    id: 2,
                    name: "two".to_string(),
                    values: vec![2],
                },
            ),
            (
                "key3",
                TestItem {
                    id: 3,
                    name: "three".to_string(),
                    values: vec![3],
                },
            ),
        ];

        for (key, item) in &items {
            collection.set(key, item);
        }

        let entries = collection.entries();
        assert_eq!(entries.len(), 3);

        // Convert to map for easier verification
        let map: std::collections::HashMap<String, TestItem> = entries.into_iter().collect();

        for (key, item) in items {
            assert_eq!(map.get(key), Some(&item));
        }
    }

    #[test]
    fn test_collection_overwrite() {
        let (storage, _temp) = create_test_storage();
        let collection: Collection<TestItem> = storage.collection("test").unwrap();

        let item1 = TestItem {
            id: 1,
            name: "first".to_string(),
            values: vec![1],
        };
        let item2 = TestItem {
            id: 2,
            name: "second".to_string(),
            values: vec![2],
        };

        collection.set("key", &item1);
        assert_eq!(collection.get("key"), Some(item1));

        collection.set("key", &item2);
        assert_eq!(collection.get("key"), Some(item2));
    }

    #[test]
    fn test_multiple_collections() {
        let (storage, _temp) = create_test_storage();

        let coll1: Collection<TestItem> = storage.collection("collection1").unwrap();
        let coll2: Collection<TestItem> = storage.collection("collection2").unwrap();

        let item1 = TestItem {
            id: 1,
            name: "in1".to_string(),
            values: vec![],
        };
        let item2 = TestItem {
            id: 2,
            name: "in2".to_string(),
            values: vec![],
        };

        coll1.set("key", &item1);
        coll2.set("key", &item2);

        // Same key, different collections
        assert_eq!(coll1.get("key"), Some(item1));
        assert_eq!(coll2.get("key"), Some(item2));
    }

    #[test]
    fn test_collection_empty_entries() {
        let (storage, _temp) = create_test_storage();
        let collection: Collection<TestItem> = storage.collection("empty").unwrap();

        let entries = collection.entries();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_collection_different_types() {
        let (storage, _temp) = create_test_storage();

        // String collection
        let strings: Collection<String> = storage.collection("strings").unwrap();
        strings.set("key", &"hello".to_string());
        assert_eq!(strings.get("key"), Some("hello".to_string()));

        // U64 collection
        let numbers: Collection<u64> = storage.collection("numbers").unwrap();
        numbers.set("key", &42u64);
        assert_eq!(numbers.get("key"), Some(42u64));
    }
}
