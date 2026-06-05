package main

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/frost-taproot/frost-taproot-go/types"
)

type memBackend struct {
	mu   sync.Mutex
	data map[string]map[string][]byte
}

func newMemBackend() *memBackend {
	return &memBackend{data: map[string]map[string][]byte{}}
}

func (m *memBackend) Get(collection, key string) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c := m.data[collection]; c != nil {
		return c[key]
	}
	return nil
}

func (m *memBackend) Set(collection, key string, value []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data[collection] == nil {
		m.data[collection] = map[string][]byte{}
	}
	m.data[collection][key] = value
}

func (m *memBackend) Delete(collection, key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c := m.data[collection]; c != nil {
		if _, ok := c[key]; ok {
			delete(c, key)
			return true
		}
	}
	return false
}

func (m *memBackend) Entries(collection string) map[string][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string][]byte{}
	for k, v := range m.data[collection] {
		out[k] = v
	}
	return out
}

func newTestSigner() *Signer {
	return OpenSigner(SignerOptions{URL: "http://test"}, newMemBackend())
}

// Concurrent completions for one commit id must yield at most one take.
func TestTakeCommitSingleUseConcurrent(t *testing.T) {
	s := newTestSigner()
	id := s.putCommit("client-a", &commitEntry{secret: types.SecretNonce{ID: 1}, createdAt: nowSec()})

	const n = 64
	var success int64
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if _, taken := s.takeCommit(id, "client-a"); taken {
				atomic.AddInt64(&success, 1)
			}
		}()
	}
	wg.Wait()

	if success != 1 {
		t.Fatalf("expected exactly one successful take, got %d", success)
	}
	if _, taken := s.takeCommit(id, "client-a"); taken {
		t.Fatal("replay take succeeded after consumption")
	}
}

// A take by the wrong client must be refused (and must not consume the entry).
func TestTakeCommitWrongClient(t *testing.T) {
	s := newTestSigner()
	id := s.putCommit("client-a", &commitEntry{secret: types.SecretNonce{ID: 1}, createdAt: nowSec()})
	if _, taken := s.takeCommit(id, "client-b"); taken {
		t.Fatal("take by wrong client succeeded")
	}
	if _, taken := s.takeCommit(id, "client-a"); !taken {
		t.Fatal("legitimate take failed after wrong-client attempt")
	}
}

// cleanup reaps commits older than the TTL.
func TestCleanupReapsExpiredCommits(t *testing.T) {
	s := newTestSigner()
	staleID := s.putCommit("client-a", &commitEntry{createdAt: nowSec() - commitTTLSecs - 1})
	freshID := s.putCommit("client-a", &commitEntry{createdAt: nowSec()})

	s.cleanup()

	if _, taken := s.takeCommit(staleID, "client-a"); taken {
		t.Fatal("stale commit should have been reaped")
	}
	if _, taken := s.takeCommit(freshID, "client-a"); !taken {
		t.Fatal("fresh commit should have survived cleanup")
	}
}
