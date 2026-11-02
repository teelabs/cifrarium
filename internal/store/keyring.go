package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/user"

	"github.com/teelabs/cifrarium/internal/recovery"
	"github.com/zalando/go-keyring"
)

const service = "cifrarium"

type secrets struct {
	Operational    string `json:"operational"`
	SigningPrivate string `json:"signing_private"`
	CatalogHead    string `json:"catalog_head,omitempty"`
}
type recoveryBundle struct {
	Version        int    `json:"version"`
	Operational    string `json:"operational"`
	SigningPrivate string `json:"signing_private"`
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
		if len(operational) != 32 {
			return nil, nil, fmt.Errorf("invalid operational key length")
		}
		p, err := base64.RawStdEncoding.DecodeString(s.SigningPrivate)
		if err != nil {
			return nil, nil, err
		}
		if len(p) != ed25519.PrivateKeySize {
			return nil, nil, fmt.Errorf("invalid signing key length")
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

// RecoveryShares encodes both keyring secrets so a fresh environment can
// reopen an existing vault, not merely decrypt new snapshots.
func RecoveryShares(operational []byte, signing ed25519.PrivateKey) ([]recovery.Share, error) {
	if len(operational) != 32 || len(signing) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid key material")
	}
	bundle := recoveryBundle{
		Version:        1,
		Operational:    base64.RawStdEncoding.EncodeToString(operational),
		SigningPrivate: base64.RawStdEncoding.EncodeToString(signing),
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		return nil, err
	}
	return recovery.Split(raw)
}

func RecoverKeys(shares []recovery.Share) ([]byte, ed25519.PrivateKey, error) {
	raw, err := recovery.Combine(shares)
	if err != nil {
		return nil, nil, err
	}
	var bundle recoveryBundle
	if err := json.Unmarshal(raw, &bundle); err != nil || bundle.Version != 1 {
		return nil, nil, fmt.Errorf("invalid recovery bundle")
	}
	op, err := base64.RawStdEncoding.DecodeString(bundle.Operational)
	if err != nil || len(op) != 32 {
		return nil, nil, fmt.Errorf("invalid recovered operational key")
	}
	signing, err := base64.RawStdEncoding.DecodeString(bundle.SigningPrivate)
	if err != nil || len(signing) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("invalid recovered signing key")
	}
	return op, ed25519.PrivateKey(signing), nil
}

// ImportRecovery replaces the local keyring entry after explicit operator
// recovery. The catalog head is intentionally reset and re-established by
// OpenWithGuard after the existing signed chain is verified.
func (k *Keyring) ImportRecovery(shares []recovery.Share) error {
	op, signing, err := RecoverKeys(shares)
	if err != nil {
		return err
	}
	s := secrets{
		Operational:    base64.RawStdEncoding.EncodeToString(op),
		SigningPrivate: base64.RawStdEncoding.EncodeToString(signing),
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return keyring.Set(service, k.User, string(b))
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
