use std::marker::PhantomData;
use std::sync::Arc;

use chacha20poly1305::{XChaCha20Poly1305, XNonce, aead::Aead, aead::KeyInit};
use rand::RngCore;
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

// ---- Backend trait ----

pub trait StorageBackend: Send + Sync + 'static {
    fn get(&self, collection: &str, key: &str) -> Option<Vec<u8>>;
    fn set(&self, collection: &str, key: &str, value: &[u8]);
    fn delete(&self, collection: &str, key: &str) -> bool;
    fn entries(&self, collection: &str) -> Vec<(String, Vec<u8>)>;
}

// ---- Collection ----

pub struct Collection<T> {
    name: String,
    backend: Arc<dyn StorageBackend>,
    _marker: PhantomData<T>,
}

impl<T> Collection<T>
where
    T: Serialize + DeserializeOwned,
{
    pub fn get(&self, key: &str) -> Option<T> {
        self.backend
            .get(&self.name, key)
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    }

    pub fn set(&self, key: &str, value: &T) {
        if let Ok(bytes) = serde_json::to_vec(value) {
            self.backend.set(&self.name, key, &bytes);
        }
    }

    pub fn delete(&self, key: &str) -> bool {
        self.backend.delete(&self.name, key)
    }

    pub fn entries(&self) -> Vec<(String, T)> {
        self.backend
            .entries(&self.name)
            .into_iter()
            .filter_map(|(k, v)| {
                let value = serde_json::from_slice(&v).ok()?;
                Some((k, value))
            })
            .collect()
    }
}

// ---- Storage (collection factory) ----

pub struct Storage {
    backend: Arc<dyn StorageBackend>,
}

impl Storage {
    pub fn new(backend: impl StorageBackend) -> Self {
        Self {
            backend: Arc::new(backend),
        }
    }

    pub fn collection<T>(&self, name: &str) -> Collection<T> {
        Collection {
            name: name.to_string(),
            backend: Arc::clone(&self.backend),
            _marker: PhantomData,
        }
    }
}

// ---- Sled backend ----

const NONCE_LEN: usize = 24;

pub struct SledBackend {
    db: sled::Db,
    cipher: Option<XChaCha20Poly1305>,
}

impl SledBackend {
    #[cfg(test)]
    pub fn open(path: impl AsRef<std::path::Path>) -> sled::Result<Self> {
        Ok(Self {
            db: sled::open(path)?,
            cipher: None,
        })
    }

    /// Open with encryption. `secret` is hashed with SHA-256 to produce the key.
    pub fn open_encrypted(path: impl AsRef<std::path::Path>, secret: &str) -> sled::Result<Self> {
        let key: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
        Ok(Self {
            db: sled::open(path)?,
            cipher: Some(XChaCha20Poly1305::new_from_slice(&key).expect("invalid key length")),
        })
    }

    fn tree(&self, collection: &str) -> sled::Tree {
        self.db
            .open_tree(collection)
            .expect("sled tree open failed")
    }

    fn encode(&self, plaintext: &[u8]) -> Vec<u8> {
        let Some(cipher) = &self.cipher else {
            return plaintext.to_vec();
        };
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .expect("encryption failed");
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    fn decode(&self, value: &[u8]) -> Option<Vec<u8>> {
        let Some(cipher) = &self.cipher else {
            return Some(value.to_vec());
        };
        if value.len() <= NONCE_LEN {
            return None;
        }
        let nonce = XNonce::from(<[u8; NONCE_LEN]>::try_from(&value[..NONCE_LEN]).ok()?);
        cipher.decrypt(&nonce, &value[NONCE_LEN..]).ok()
    }
}

impl StorageBackend for SledBackend {
    fn get(&self, collection: &str, key: &str) -> Option<Vec<u8>> {
        let raw = self.tree(collection).get(key).ok().flatten()?;
        self.decode(&raw)
    }

    fn set(&self, collection: &str, key: &str, value: &[u8]) {
        let _ = self.tree(collection).insert(key, self.encode(value));
    }

    fn delete(&self, collection: &str, key: &str) -> bool {
        self.tree(collection).remove(key).ok().flatten().is_some()
    }

    fn entries(&self, collection: &str) -> Vec<(String, Vec<u8>)> {
        self.tree(collection)
            .iter()
            .filter_map(|r| r.ok())
            .filter_map(|(k, v)| {
                let key = String::from_utf8(k.to_vec()).ok()?;
                let value = self.decode(&v)?;
                Some((key, value))
            })
            .collect()
    }
}

// ---- Tests ----

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
        let backend = SledBackend::open(temp_dir.path().join("test.db")).unwrap();
        (Storage::new(backend), temp_dir)
    }

    #[test]
    fn test_storage_open() {
        let (storage, _temp) = create_test_storage();
        drop(storage);
    }

    #[test]
    fn test_collection_get_set() {
        let (storage, _temp) = create_test_storage();
        let collection: Collection<TestItem> = storage.collection("test");

        let item = TestItem {
            id: 1,
            name: "test".to_string(),
            values: vec![1, 2, 3],
        };

        assert!(collection.get("key1").is_none());

        collection.set("key1", &item);
        let retrieved = collection.get("key1");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), item);
    }

    #[test]
    fn test_collection_delete() {
        let (storage, _temp) = create_test_storage();
        let collection: Collection<TestItem> = storage.collection("test");

        let item = TestItem {
            id: 1,
            name: "test".to_string(),
            values: vec![],
        };

        collection.set("key1", &item);
        assert!(collection.get("key1").is_some());

        assert!(collection.delete("key1"));
        assert!(collection.get("key1").is_none());

        assert!(!collection.delete("nonexistent"));
    }

    #[test]
    fn test_collection_entries() {
        let (storage, _temp) = create_test_storage();
        let collection: Collection<TestItem> = storage.collection("test");

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

        let map: std::collections::HashMap<String, TestItem> = entries.into_iter().collect();
        for (key, item) in items {
            assert_eq!(map.get(key), Some(&item));
        }
    }

    #[test]
    fn test_collection_overwrite() {
        let (storage, _temp) = create_test_storage();
        let collection: Collection<TestItem> = storage.collection("test");

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

        let coll1: Collection<TestItem> = storage.collection("collection1");
        let coll2: Collection<TestItem> = storage.collection("collection2");

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

        assert_eq!(coll1.get("key"), Some(item1));
        assert_eq!(coll2.get("key"), Some(item2));
    }

    #[test]
    fn test_collection_empty_entries() {
        let (storage, _temp) = create_test_storage();
        let collection: Collection<TestItem> = storage.collection("empty");
        assert!(collection.entries().is_empty());
    }

    #[test]
    fn test_collection_different_types() {
        let (storage, _temp) = create_test_storage();

        let strings: Collection<String> = storage.collection("strings");
        strings.set("key", &"hello".to_string());
        assert_eq!(strings.get("key"), Some("hello".to_string()));

        let numbers: Collection<u64> = storage.collection("numbers");
        numbers.set("key", &42u64);
        assert_eq!(numbers.get("key"), Some(42u64));
    }

    #[test]
    fn test_encrypted_round_trip_and_plaintext_not_stored() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test.db");

        let item = TestItem {
            id: 7,
            name: "encrypted".to_string(),
            values: vec![10, 20],
        };
        let plaintext = serde_json::to_vec(&item).unwrap();

        {
            let backend = SledBackend::open_encrypted(&path, "test-secret").unwrap();
            let storage = Storage::new(backend);
            let collection: Collection<TestItem> = storage.collection("sessions");
            collection.set("k1", &item);
            assert_eq!(collection.get("k1"), Some(item.clone()));
        }

        // Verify the raw bytes on disk are not the plaintext
        let raw_backend = SledBackend::open(&path).unwrap();
        let at_rest = raw_backend.get("sessions", "k1").unwrap();
        assert_ne!(at_rest, plaintext);
        assert!(at_rest.len() > NONCE_LEN);
    }

    #[test]
    fn test_encrypted_wrong_secret_cannot_decrypt() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test.db");

        {
            let writer = Storage::new(SledBackend::open_encrypted(&path, "secret-a").unwrap());
            let collection: Collection<String> = writer.collection("sessions");
            collection.set("k1", &"value".to_string());
        }

        let reader = Storage::new(SledBackend::open_encrypted(&path, "secret-b").unwrap());
        let collection: Collection<String> = reader.collection("sessions");
        assert_eq!(collection.get("k1"), None);
    }
}
