package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestQueueLimit(t *testing.T) {
	q := Queue{}
	for i := 0; i < MaxPending; i++ {
		if err := q.Push(Item{ID: "x", Ciphertext: []byte("x")}); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.Push(Item{ID: "overflow", Ciphertext: []byte("x")}); err == nil {
		t.Fatal("overflow accepted")
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
