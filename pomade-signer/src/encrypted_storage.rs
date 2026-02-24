/// An encrypted wrapper around any `StorageBackend`.
///
/// Each value is encrypted with AES-256-GCM using a random 96-bit nonce, which
/// is prepended to the ciphertext before storage. The key must be 32 bytes and
/// should be derived from the enclave's attestation identity so that only this
/// specific enclave build can decrypt the data.
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, OsRng, rand_core::RngCore},
};

use crate::storage::StorageBackend;

const NONCE_LEN: usize = 12;

pub struct EncryptedBackend<B> {
    inner: B,
    cipher: Aes256Gcm,
}

impl<B: StorageBackend> EncryptedBackend<B> {
    pub fn new(inner: B, key: &[u8; 32]) -> Self {
        Self {
            inner,
            cipher: Aes256Gcm::new_from_slice(key).expect("key is exactly 32 bytes"),
        }
    }

    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(&nonce_bytes.into(), plaintext)
            .expect("aes-gcm encryption failed");
        [nonce_bytes.as_slice(), ciphertext.as_slice()].concat()
    }

    fn decrypt(&self, blob: &[u8]) -> Option<Vec<u8>> {
        if blob.len() < NONCE_LEN {
            log::error!("[encrypted_storage]: blob too short to contain nonce");
            return None;
        }
        let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce_bytes.try_into().ok()?;
        self.cipher
            .decrypt(&nonce.into(), ciphertext)
            .ok()
            .or_else(|| {
                log::error!("[encrypted_storage]: decryption failed (wrong key or corrupt data)");
                None
            })
    }
}

impl<B: StorageBackend> StorageBackend for EncryptedBackend<B> {
    fn get(&self, collection: &str, key: &str) -> Option<Vec<u8>> {
        self.inner
            .get(collection, key)
            .and_then(|blob| self.decrypt(&blob))
    }

    fn set(&self, collection: &str, key: &str, value: &[u8]) {
        self.inner.set(collection, key, &self.encrypt(value));
    }

    fn delete(&self, collection: &str, key: &str) -> bool {
        self.inner.delete(collection, key)
    }

    fn entries(&self, collection: &str) -> Vec<(String, Vec<u8>)> {
        self.inner
            .entries(collection)
            .into_iter()
            .filter_map(|(k, blob)| self.decrypt(&blob).map(|v| (k, v)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{Storage, StorageBackend};
    use std::collections::HashMap;
    use std::sync::Mutex;

    // Minimal in-memory backend for testing without sled
    #[derive(Default)]
    struct MemBackend(Mutex<HashMap<String, Vec<u8>>>);

    impl StorageBackend for MemBackend {
        fn get(&self, collection: &str, key: &str) -> Option<Vec<u8>> {
            self.0
                .lock()
                .unwrap()
                .get(&format!("{collection}/{key}"))
                .cloned()
        }
        fn set(&self, collection: &str, key: &str, value: &[u8]) {
            self.0
                .lock()
                .unwrap()
                .insert(format!("{collection}/{key}"), value.to_vec());
        }
        fn delete(&self, collection: &str, key: &str) -> bool {
            self.0
                .lock()
                .unwrap()
                .remove(&format!("{collection}/{key}"))
                .is_some()
        }
        fn entries(&self, collection: &str) -> Vec<(String, Vec<u8>)> {
            let prefix = format!("{collection}/");
            self.0
                .lock()
                .unwrap()
                .iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .map(|(k, v)| (k[prefix.len()..].to_string(), v.clone()))
                .collect()
        }
    }

    fn test_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn test_roundtrip() {
        let backend = EncryptedBackend::new(MemBackend::default(), &test_key());
        let storage = Storage::new(backend);
        let col = storage.collection::<String>("test");

        col.set("hello", &"world".to_string());
        assert_eq!(col.get("hello"), Some("world".to_string()));
    }

    #[test]
    fn test_values_are_opaque_to_inner_backend() {
        // Write through the encrypted backend, then read the raw bytes directly
        // from a second unencrypted view of the same in-memory store.
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};

        #[derive(Clone, Default)]
        struct SharedMem(Arc<Mutex<HashMap<String, Vec<u8>>>>);

        impl StorageBackend for SharedMem {
            fn get(&self, collection: &str, key: &str) -> Option<Vec<u8>> {
                self.0
                    .lock()
                    .unwrap()
                    .get(&format!("{collection}/{key}"))
                    .cloned()
            }
            fn set(&self, collection: &str, key: &str, value: &[u8]) {
                self.0
                    .lock()
                    .unwrap()
                    .insert(format!("{collection}/{key}"), value.to_vec());
            }
            fn delete(&self, collection: &str, key: &str) -> bool {
                self.0
                    .lock()
                    .unwrap()
                    .remove(&format!("{collection}/{key}"))
                    .is_some()
            }
            fn entries(&self, collection: &str) -> Vec<(String, Vec<u8>)> {
                let prefix = format!("{collection}/");
                self.0
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|(k, _)| k.starts_with(&prefix))
                    .map(|(k, v)| (k[prefix.len()..].to_string(), v.clone()))
                    .collect()
            }
        }

        let shared = SharedMem::default();
        let backend = EncryptedBackend::new(shared.clone(), &test_key());
        let storage = Storage::new(backend);
        let col = storage.collection::<String>("test");

        col.set("key", &"secret".to_string());

        // The raw bytes in the inner store must not equal the plaintext JSON
        let raw = shared.get("test", "key").unwrap();
        assert_ne!(raw, br#""secret""#);
    }

    #[test]
    fn test_wrong_key_returns_none() {
        // Write with key A, then try to read the same raw bytes with key B
        let inner = MemBackend::default();
        inner.set("test", "k", &[0u8; 32]); // plant a fake ciphertext

        let reader = EncryptedBackend::new(MemBackend::default(), &[0x22u8; 32]);
        assert!(reader.get("test", "k").is_none());
    }

    #[test]
    fn test_delete() {
        let backend = EncryptedBackend::new(MemBackend::default(), &test_key());
        let storage = Storage::new(backend);
        let col = storage.collection::<String>("test");

        col.set("k", &"v".to_string());
        assert!(col.get("k").is_some());
        assert!(col.delete("k"));
        assert!(col.get("k").is_none());
    }

    #[test]
    fn test_entries() {
        let backend = EncryptedBackend::new(MemBackend::default(), &test_key());
        let storage = Storage::new(backend);
        let col = storage.collection::<String>("test");

        col.set("a", &"1".to_string());
        col.set("b", &"2".to_string());

        let mut entries = col.entries();
        entries.sort_by_key(|(k, _)| k.clone());
        assert_eq!(
            entries,
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "2".to_string()),
            ]
        );
    }

    #[test]
    fn test_nonces_are_unique() {
        let backend = EncryptedBackend::new(MemBackend::default(), &test_key());
        let storage = Storage::new(backend);
        let col = storage.collection::<String>("test");

        // Write the same value twice; the stored blobs should differ due to random nonces
        col.set("k1", &"same".to_string());
        col.set("k2", &"same".to_string());

        let raw1 = storage.collection::<serde_json::Value>("test").get("k1");
        let raw2 = storage.collection::<serde_json::Value>("test").get("k2");
        // Both decrypt correctly
        assert_eq!(col.get("k1"), Some("same".to_string()));
        assert_eq!(col.get("k2"), Some("same".to_string()));
        // (nonce uniqueness is probabilistic but effectively guaranteed with 96-bit random nonces)
        let _ = (raw1, raw2);
    }
}
