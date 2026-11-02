package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/user"

	"github.com/zalando/go-keyring"
)

const service = "cifrarium"

type secrets struct {
	Operational    string `json:"operational"`
	SigningPrivate string `json:"signing_private"`
	CatalogHead    string `json:"catalog_head,omitempty"`
}
type Keyring struct{ User string }

func NewKeyring() *Keyring {
	u, _ := user.Current()
	id := "unknown"
	if u != nil {
		id = u.Uid
	}
	return &Keyring{User: id}
}
func (k *Keyring) LoadOrCreate() (operational []byte, signing ed25519.PrivateKey, err error) {
	raw, err := keyring.Get(service, k.User)
	if err == nil {
		var s secrets
		if json.Unmarshal([]byte(raw), &s) != nil {
			return nil, nil, fmt.Errorf("invalid keyring payload")
		}
		operational, err = base64.RawStdEncoding.DecodeString(s.Operational)
		if err != nil {
			return nil, nil, err
		}
		p, err := base64.RawStdEncoding.DecodeString(s.SigningPrivate)
		if err != nil {
			return nil, nil, err
		}
		return operational, ed25519.PrivateKey(p), nil
	}
	operational = make([]byte, 32)
	if _, err = rand.Read(operational); err != nil {
		return nil, nil, err
	}
	_, signing, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	s := secrets{Operational: base64.RawStdEncoding.EncodeToString(operational), SigningPrivate: base64.RawStdEncoding.EncodeToString(signing)}
	b, _ := json.Marshal(s)
	if err = keyring.Set(service, k.User, string(b)); err != nil {
		return nil, nil, fmt.Errorf("keyring unavailable: %w", err)
	}
	return operational, signing, nil
}

func (k *Keyring) load() (secrets, error) {
	raw, err := keyring.Get(service, k.User)
	if err != nil {
		return secrets{}, err
	}
	var s secrets
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return secrets{}, err
	}
	return s, nil
}
func (k *Keyring) CatalogHead() (string, error) { s, err := k.load(); return s.CatalogHead, err }
func (k *Keyring) SetCatalogHead(head string) error {
	s, err := k.load()
	if err != nil {
		return err
	}
	s.CatalogHead = head
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return keyring.Set(service, k.User, string(b))
}
