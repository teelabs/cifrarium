package daemon

import (
	"encoding/json"
	"fmt"
	"os"

	crypt "github.com/teelabs/cifrarium/internal/crypto"
)

const MaxPending = 16

type Item struct {
	ID         string
	Ciphertext []byte
}
type Queue struct{ items []Item }

func (q *Queue) Push(item Item) error {
	if item.ID == "" || len(item.Ciphertext) == 0 {
		return fmt.Errorf("invalid pending item")
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
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, ciphertext, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func Load(path string, operationalKey []byte) (*Queue, error) {
	ciphertext, err := os.ReadFile(path)
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
	if len(items) > MaxPending {
		return nil, fmt.Errorf("pending queue exceeds limit")
	}
	return &Queue{items: items}, nil
}
