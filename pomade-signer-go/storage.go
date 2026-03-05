package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"go.etcd.io/bbolt"
	"golang.org/x/crypto/chacha20poly1305"
)

const nonceLen = chacha20poly1305.NonceSizeX

type StorageBackend interface {
	Get(collection string, key string) []byte
	Set(collection string, key string, value []byte)
	Delete(collection string, key string) bool
	Entries(collection string) map[string][]byte
}

type Collection[T any] struct {
	name    string
	backend StorageBackend
}

func (c Collection[T]) Get(key string) *T {
	b := c.backend.Get(c.name, key)
	if b == nil {
		return nil
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return nil
	}
	return &v
}

func (c Collection[T]) Set(key string, value T) {
	b, err := json.Marshal(value)
	if err != nil {
		return
	}
	c.backend.Set(c.name, key, b)
}

func (c Collection[T]) Delete(key string) bool {
	return c.backend.Delete(c.name, key)
}

func (c Collection[T]) Entries() map[string]T {
	entries := c.backend.Entries(c.name)
	out := make(map[string]T, len(entries))
	for k, v := range entries {
		var item T
		if err := json.Unmarshal(v, &item); err != nil {
			continue
		}
		out[k] = item
	}
	return out
}

type Storage struct {
	backend StorageBackend
}

func NewStorage(backend StorageBackend) Storage {
	return Storage{backend: backend}
}

func GetCollection[T any](s Storage, name string) Collection[T] {
	return Collection[T]{name: name, backend: s.backend}
}

type BboltBackend struct {
	db     *bbolt.DB
	aead   cipherLike
	sealed bool
}

type cipherLike interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	NonceSize() int
}

func OpenBbolt(path string) (*BboltBackend, error) {
	db, err := bbolt.Open(path, 0o600, nil)
	if err != nil {
		return nil, err
	}
	return &BboltBackend{db: db}, nil
}

func OpenBboltEncrypted(path string, secret string) (*BboltBackend, error) {
	db, err := bbolt.Open(path, 0o600, nil)
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256([]byte(secret))
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		db.Close()
		return nil, err
	}
	return &BboltBackend{db: db, aead: aead, sealed: true}, nil
}

func (b *BboltBackend) Close() error {
	if b == nil || b.db == nil {
		return nil
	}
	return b.db.Close()
}

func (b *BboltBackend) Get(collection string, key string) []byte {
	var out []byte
	_ = b.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(collection))
		if bucket == nil {
			return nil
		}
		raw := bucket.Get([]byte(key))
		if raw == nil {
			return nil
		}
		v, err := b.decode(raw)
		if err != nil {
			return nil
		}
		out = v
		return nil
	})
	return out
}

func (b *BboltBackend) Set(collection string, key string, value []byte) {
	_ = b.db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(collection))
		if err != nil {
			return err
		}
		enc, err := b.encode(value)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(key), enc)
	})
}

func (b *BboltBackend) Delete(collection string, key string) bool {
	deleted := false
	_ = b.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(collection))
		if bucket == nil {
			return nil
		}
		if bucket.Get([]byte(key)) != nil {
			deleted = true
		}
		return bucket.Delete([]byte(key))
	})
	return deleted
}

func (b *BboltBackend) Entries(collection string) map[string][]byte {
	out := map[string][]byte{}
	_ = b.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(collection))
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(k, v []byte) error {
			dec, err := b.decode(v)
			if err != nil {
				return nil
			}
			out[string(k)] = dec
			return nil
		})
	})
	return out
}

func (b *BboltBackend) encode(plaintext []byte) ([]byte, error) {
	if !b.sealed {
		return append([]byte(nil), plaintext...), nil
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := b.aead.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, nonceLen+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

func (b *BboltBackend) decode(value []byte) ([]byte, error) {
	if !b.sealed {
		return append([]byte(nil), value...), nil
	}
	if len(value) <= nonceLen {
		return nil, errors.New("invalid encrypted payload")
	}
	nonce := value[:nonceLen]
	ct := value[nonceLen:]
	return b.aead.Open(nil, nonce, ct, nil)
}
