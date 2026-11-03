package daemon

import (
	"encoding/json"
	"fmt"
	"os"

	crypt "github.com/teelabs/cifrarium/internal/crypto"
	"github.com/teelabs/cifrarium/internal/limits"
)

const MaxPending = 16

type Item struct {
	ID         string
	Ciphertext []byte
	Manifest   []byte
}
type Queue struct{ items []Item }

func (q *Queue) Push(item Item) error {
	if err := validateItem(item); err != nil {
		return err
	}
	if len(q.items) >= MaxPending {
		return fmt.Errorf("pending queue is full")
	}
	q.items = append(q.items, item)
	return nil
}
func (q *Queue) Pop() (Item, bool) {
	if len(q.items) == 0 {
		return Item{}, false
	}
	item := q.items[0]
	q.items = q.items[1:]
	return item, true
}
func (q *Queue) Len() int { return len(q.items) }

func (q *Queue) Save(path string, operationalKey []byte) error {
	raw, err := json.Marshal(q.items)
	if err != nil {
		return err
	}
	ciphertext, err := crypt.Seal(raw, operationalKey)
	if err != nil {
		return err
	}
	if err := limits.CheckBytes(len(ciphertext), limits.MaxQueueFileBytes); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, ciphertext, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func Load(path string, operationalKey []byte) (*Queue, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ciphertext, err := limits.ReadAll(f, limits.MaxQueueFileBytes)
	if err != nil {
		return nil, err
	}
	raw, err := crypt.Open(ciphertext, operationalKey)
	if err != nil {
		return nil, err
	}
	var items []Item
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, err
	}
	for _, item := range items {
		if err := validateItem(item); err != nil {
			return nil, err
		}
	}
	if len(items) > MaxPending {
		return nil, fmt.Errorf("pending queue exceeds limit")
	}
	return &Queue{items: items}, nil
}

func validateItem(item Item) error {
	if item.ID == "" || len(item.Ciphertext) == 0 {
		return fmt.Errorf("invalid pending item")
	}
	if err := limits.CheckBytes(len(item.ID), int64(limits.MaxPathBytes)); err != nil {
		return fmt.Errorf("pending item id: %w", err)
	}
	if err := limits.CheckBytes(len(item.Ciphertext), limits.MaxQueueItemBytes); err != nil {
		return err
	}
	return limits.CheckBytes(len(item.Manifest), limits.MaxManifestBytes)
}
