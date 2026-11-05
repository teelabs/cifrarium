package daemon

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/teelabs/cifrarium/internal/limits"
)

func TestQueueLimit(t *testing.T) {
	q := Queue{}
	for i := 0; i < MaxPending; i++ {
		if err := q.Push(Item{ID: "x", Ciphertext: []byte("x")}); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.Push(Item{ID: "overflow", Ciphertext: []byte("x")}); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("overflow error = %v, want ErrQueueFull", err)
	}
	if q.Len() != MaxPending {
		t.Fatal(q.Len())
	}
}
func TestQueuePersistsEncrypted(t *testing.T) {
	q := Queue{}
	if err := q.Push(Item{ID: "id", Ciphertext: []byte("cipher")}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "queue")
	key := make([]byte, 32)
	if err := q.Save(path, key); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if string(raw) == "[{\"ID\":\"id\",\"Ciphertext\":\"Y2lwaGVy\"}]" {
		t.Fatal("queue plaintext")
	}
	got, err := Load(path, key)
	if err != nil || got.Len() != 1 {
		t.Fatalf("load: %v", err)
	}
}

func TestQueueRejectsOversizedItem(t *testing.T) {
	var q Queue
	if err := q.Push(Item{ID: "large", Ciphertext: bytes.Repeat([]byte("x"), int(limits.MaxQueueItemBytes)+1)}); err == nil {
		t.Fatal("oversized queue item accepted")
	}
}

func TestQueueRejectsOversizedItemID(t *testing.T) {
	var q Queue
	if err := q.Push(Item{ID: strings.Repeat("x", limits.MaxPathBytes+1), Ciphertext: []byte("cipher")}); err == nil {
		t.Fatal("oversized queue item id accepted")
	}
}

func TestQueueConcurrentAccessIsSynchronized(t *testing.T) {
	q := &Queue{}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = q.Push(Item{ID: "id", Ciphertext: []byte("cipher")})
				_, _ = q.Pop()
				_ = q.Len()
			}
		}()
	}
	wg.Wait()
}
