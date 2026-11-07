package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"

	"github.com/teelabs/cifrarium/internal/recovery"
	"github.com/zalando/go-keyring"
)

const service = "cifrarium"

type secrets struct {
	Operational    string `json:"operational"`
	SigningPrivate string `json:"signing_private"`
	CatalogHead    string `json:"catalog_head,omitempty"`
	Root           string `json:"root,omitempty"`
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
	return loadOrCreate(
		k.User,
		func(service, user string) (string, error) { return keyring.Get(service, user) },
		func(service, user, password string) error { return keyring.Set(service, user, password) },
	)
}

// LoadOrCreateForRoot binds newly created or explicitly adopted legacy keyring
// material to the canonical vault root. Normal commands should use
// LoadExistingForRoot so diagnostics and reads never create or rewrite state.
func (k *Keyring) LoadOrCreateForRoot(root string, bindLegacy bool) ([]byte, ed25519.PrivateKey, error) {
	return loadOrCreateBound(k.User, root, bindLegacy,
		func(service, user string) (string, error) { return keyring.Get(service, user) },
		func(service, user, password string) error { return keyring.Set(service, user, password) },
	)
}

func GenerateKeyMaterial() ([]byte, ed25519.PrivateKey, error) {
	operational := make([]byte, 32)
	if _, err := rand.Read(operational); err != nil {
		return nil, nil, err
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return operational, signing, nil
}

// SaveForRoot persists already-generated material after an interactive setup
// confirmation. It validates the material before changing the keyring and
// preserves an existing catalog guard.
func (k *Keyring) SaveForRoot(root string, operational []byte, signing ed25519.PrivateKey) error {
	if len(operational) != 32 || len(signing) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid key material")
	}
	raw, err := keyring.Get(service, k.User)
	current := secrets{}
	if err == nil {
		current, err = decodePayload(raw)
		if err != nil {
			return err
		}
		if current.Root != "" && current.Root != root {
			return fmt.Errorf("keyring is bound to a different vault root")
		}
		if current.Operational != "" || current.SigningPrivate != "" {
			if _, _, err := decodeSecrets(raw); err != nil {
				return err
			}
		}
	} else if !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("keyring unavailable: %w", err)
	}
	payload := secrets{
		Operational:    base64.RawStdEncoding.EncodeToString(operational),
		SigningPrivate: base64.RawStdEncoding.EncodeToString(signing),
		CatalogHead:    current.CatalogHead,
		Root:           root,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := keyring.Set(service, k.User, string(encoded)); err != nil {
		return fmt.Errorf("keyring unavailable: %w", err)
	}
	return nil
}

// DeleteForRoot removes key material created for a recovery attempt only when
// the stored entry is still bound to the same root.
func (k *Keyring) DeleteForRoot(root string) error {
	raw, err := keyring.Get(service, k.User)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("keyring unavailable: %w", err)
	}
	current, err := decodePayload(raw)
	if err != nil {
		return err
	}
	if current.Root != root {
		return fmt.Errorf("refusing to remove key material for a different root")
	}
	if err := keyring.Delete(service, k.User); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("keyring unavailable: %w", err)
	}
	return nil
}

// LoadExisting reads the Cifrarium keyring entry without creating one. It is
// intended for read-only diagnostics and health checks.
func (k *Keyring) LoadExisting() (operational []byte, signing ed25519.PrivateKey, err error) {
	raw, err := keyring.Get(service, k.User)
	if err != nil {
		return nil, nil, err
	}
	return decodeSecrets(raw)
}

func (k *Keyring) LoadExistingForRoot(root string) ([]byte, ed25519.PrivateKey, error) {
	raw, err := keyring.Get(service, k.User)
	if err != nil {
		return nil, nil, err
	}
	return decodeSecretsForRoot(raw, root)
}

type keyringGet func(service, user string) (string, error)
type keyringSet func(service, user, password string) error

func loadOrCreate(user string, get keyringGet, set keyringSet) (operational []byte, signing ed25519.PrivateKey, err error) {
	raw, err := get(service, user)
	if err == nil {
		return decodeSecrets(raw)
	}
	if !errors.Is(err, keyring.ErrNotFound) {
		return nil, nil, fmt.Errorf("keyring unavailable: %w", err)
	}
	operational, signing, err = GenerateKeyMaterial()
	if err != nil {
		return nil, nil, err
	}
	s := secrets{Operational: base64.RawStdEncoding.EncodeToString(operational), SigningPrivate: base64.RawStdEncoding.EncodeToString(signing)}
	b, _ := json.Marshal(s)
	if err = set(service, user, string(b)); err != nil {
		return nil, nil, fmt.Errorf("keyring unavailable: %w", err)
	}
	return operational, signing, nil
}

func loadOrCreateBound(user, root string, bindLegacy bool, get keyringGet, set keyringSet) ([]byte, ed25519.PrivateKey, error) {
	raw, err := get(service, user)
	if err == nil {
		s, err := decodePayload(raw)
		if err != nil {
			return nil, nil, err
		}
		if s.Root != "" && s.Root != root {
			return nil, nil, fmt.Errorf("keyring is bound to a different vault root")
		}
		if s.Root == "" {
			if !bindLegacy {
				return nil, nil, fmt.Errorf("keyring has no vault root binding; run cifrarium setup --root %q", root)
			}
			if _, _, err := decodeSecrets(raw); err != nil {
				return nil, nil, err
			}
			s.Root = root
			updated, err := json.Marshal(s)
			if err != nil {
				return nil, nil, err
			}
			if err := set(service, user, string(updated)); err != nil {
				return nil, nil, fmt.Errorf("keyring unavailable: %w", err)
			}
		}
		return decodeSecrets(rawOrUpdated(s, raw))
	}
	if !errors.Is(err, keyring.ErrNotFound) {
		return nil, nil, fmt.Errorf("keyring unavailable: %w", err)
	}
	operational, signing, err := GenerateKeyMaterial()
	if err != nil {
		return nil, nil, err
	}
	s := secrets{Operational: base64.RawStdEncoding.EncodeToString(operational), SigningPrivate: base64.RawStdEncoding.EncodeToString(signing), Root: root}
	b, _ := json.Marshal(s)
	if err := set(service, user, string(b)); err != nil {
		return nil, nil, fmt.Errorf("keyring unavailable: %w", err)
	}
	return operational, signing, nil
}

func rawOrUpdated(s secrets, original string) string {
	if s.Root == "" {
		return original
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return original
	}
	return string(raw)
}

func decodeSecretsForRoot(raw, root string) ([]byte, ed25519.PrivateKey, error) {
	s, err := decodePayload(raw)
	if err != nil {
		return nil, nil, err
	}
	if s.Root == "" {
		return nil, nil, fmt.Errorf("keyring has no vault root binding; run cifrarium setup --root %q", root)
	}
	if s.Root != root {
		return nil, nil, fmt.Errorf("keyring is bound to a different vault root")
	}
	return decodeSecrets(raw)
}

func decodePayload(raw string) (secrets, error) {
	var s secrets
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return secrets{}, fmt.Errorf("invalid keyring payload")
	}
	return s, nil
}

func decodeSecrets(raw string) (operational []byte, signing ed25519.PrivateKey, err error) {
	s, err := decodePayload(raw)
	if err != nil {
		return nil, nil, err
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
// recovery while preserving a validated non-empty catalog head guard.
func (k *Keyring) ImportRecovery(root string, shares []recovery.Share) error {
	return recoverAndImport(root, k.User, shares,
		func(service, user string) (string, error) { return keyring.Get(service, user) },
		func(service, user, password string) error { return keyring.Set(service, user, password) },
	)
}

func recoverAndImport(root, user string, shares []recovery.Share, get keyringGet, set keyringSet) error {
	op, signing, err := RecoverKeys(shares)
	if err != nil {
		return err
	}
	return withVaultLock(root, func() error {
		currentRaw, currentErr := get(service, user)
		current := secrets{}
		if currentErr == nil {
			if err := json.Unmarshal([]byte(currentRaw), &current); err != nil {
				return fmt.Errorf("invalid current keyring payload: %w", err)
			}
			if current.Root != "" && current.Root != root {
				return fmt.Errorf("keyring is bound to a different vault root")
			}
		} else if !errors.Is(currentErr, keyring.ErrNotFound) {
			return fmt.Errorf("keyring unavailable: %w", currentErr)
		}
		validatedHead, err := validateRecoveredVault(root, op, signing, current.CatalogHead)
		if err != nil {
			return err
		}
		if current.CatalogHead == "" {
			current.CatalogHead = validatedHead
		}
		candidate := secrets{
			Operational:    base64.RawStdEncoding.EncodeToString(op),
			SigningPrivate: base64.RawStdEncoding.EncodeToString(signing),
			CatalogHead:    current.CatalogHead,
			Root:           root,
		}
		b, err := json.Marshal(candidate)
		if err != nil {
			return err
		}
		return set(service, user, string(b))
	})
}

func validateRecoveredVault(root string, op []byte, signing ed25519.PrivateKey, guardedHead string) (string, error) {
	v := New(root, op, signing)
	m, err := v.LoadHead()
	if os.IsNotExist(err) {
		if guardedHead != "" {
			return "", fmt.Errorf("catalog head missing while keyring guard is set")
		}
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if guardedHead != "" && guardedHead != m.Snapshot {
		return "", fmt.Errorf("catalog rollback detected")
	}
	if err := v.VerifyChain(m.Snapshot, signing.Public().(ed25519.PublicKey)); err != nil {
		return "", err
	}
	second, err := v.LoadHead()
	if err != nil {
		return "", err
	}
	if second.Snapshot != m.Snapshot {
		return "", fmt.Errorf("catalog changed during recovery validation")
	}
	return m.Snapshot, nil
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
