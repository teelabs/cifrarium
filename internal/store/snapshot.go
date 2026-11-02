package store

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	crypt "github.com/teelabs/cifrarium/internal/crypto"
)

type Record struct {
	Path string `json:"path"`
	Mode uint32 `json:"mode"`
	Data []byte `json:"data"`
}
type Manifest struct {
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	Previous  string    `json:"previous"`
	Snapshot  string    `json:"snapshot"`
	Signer    string    `json:"signer"`
	Signature string    `json:"signature"`
}
type Vault struct {
	Root        string
	Operational []byte
	Signing     ed25519.PrivateKey
	Head        string
	Guard       HeadGuard
}
type HeadGuard interface {
	CatalogHead() (string, error)
	SetCatalogHead(string) error
}

func New(root string, op []byte, signing ed25519.PrivateKey) *Vault {
	return &Vault{Root: root, Operational: op, Signing: signing}
}
func NewWithGuard(root string, op []byte, signing ed25519.PrivateKey, guard HeadGuard) *Vault {
	v := New(root, op, signing)
	v.Guard = guard
	return v
}
func Open(root string, op []byte, signing ed25519.PrivateKey) (*Vault, error) {
	return OpenWithGuard(root, op, signing, nil)
}
func OpenWithGuard(root string, op []byte, signing ed25519.PrivateKey, guard HeadGuard) (*Vault, error) {
	v := NewWithGuard(root, op, signing, guard)
	m, err := v.LoadHead()
	if os.IsNotExist(err) {
		if guard != nil {
			expected, guardErr := guard.CatalogHead()
			if guardErr != nil {
				return nil, guardErr
			}
			if expected != "" {
				return nil, fmt.Errorf("catalog head missing while keyring guard is set")
			}
		}
		return v, nil
	}
	if err != nil {
		return nil, err
	}
	if err := v.VerifyChain(m.Snapshot, signing.Public().(ed25519.PublicKey)); err != nil {
		return nil, err
	}
	if guard != nil {
		expected, err := guard.CatalogHead()
		if err != nil {
			return nil, err
		}
		if expected != "" && expected != m.Snapshot {
			return nil, fmt.Errorf("catalog rollback detected")
		}
		if expected == "" {
			if err := guard.SetCatalogHead(m.Snapshot); err != nil {
				return nil, err
			}
		}
	}
	v.Head = m.Snapshot
	return v, nil
}
func (v *Vault) Save(records []Record) (Manifest, error) {
	if err := os.MkdirAll(v.Root, 0700); err != nil {
		return Manifest{}, err
	}
	sortRecords(records)
	plain, err := json.Marshal(records)
	if err != nil {
		return Manifest{}, err
	}
	ciphertext, err := crypt.Seal(plain, v.Operational)
	if err != nil {
		return Manifest{}, err
	}
	h := sha256.Sum256(ciphertext)
	sum := hex.EncodeToString(h[:])
	m := Manifest{Version: 1, CreatedAt: time.Now().UTC(), Previous: v.Head, Snapshot: sum, Signer: crypt.Fingerprint(v.Signing.Public().(ed25519.PublicKey))}
	m.Signature = hex.EncodeToString(ed25519.Sign(v.Signing, manifestBytes(m)))
	dir := filepath.Join(v.Root, "snapshots")
	if err = os.MkdirAll(dir, 0700); err != nil {
		return Manifest{}, err
	}
	if err = writeAtomic(filepath.Join(dir, sum), ciphertext, 0600); err != nil {
		return Manifest{}, err
	}
	b, _ := json.Marshal(m)
	if err = writeAtomic(filepath.Join(v.Root, "catalog", sum+".json"), b, 0600); err != nil {
		return Manifest{}, err
	}
	if err = writeAtomic(filepath.Join(v.Root, "head.json"), b, 0600); err != nil {
		return Manifest{}, err
	}
	if v.Guard != nil {
		if err := v.Guard.SetCatalogHead(m.Snapshot); err != nil {
			return Manifest{}, err
		}
	}
	v.Head = sum
	return m, nil
}
func (v *Vault) Verify(m Manifest, pub ed25519.PublicKey) error {
	if m.Version != 1 {
		return fmt.Errorf("unsupported manifest")
	}
	sig, err := hex.DecodeString(m.Signature)
	if err != nil || !ed25519.Verify(pub, manifestBytes(m), sig) {
		return fmt.Errorf("invalid manifest signature")
	}
	if m.Signer != crypt.Fingerprint(pub) {
		return fmt.Errorf("manifest signer mismatch")
	}
	if m.Previous == m.Snapshot {
		return fmt.Errorf("self-referential catalog")
	}
	return nil
}

func (v *Vault) LoadHead() (Manifest, error) {
	raw, err := os.ReadFile(filepath.Join(v.Root, "head.json"))
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func (v *Vault) VerifyChain(head string, pub ed25519.PublicKey) error {
	if head == "" || filepath.Base(head) != head {
		return fmt.Errorf("invalid catalog head")
	}
	seen := map[string]bool{}
	for current, depth := head, 0; current != ""; depth++ {
		if depth > 1024 || seen[current] {
			return fmt.Errorf("catalog chain loop or excessive depth")
		}
		seen[current] = true
		raw, err := os.ReadFile(filepath.Join(v.Root, "catalog", current+".json"))
		if err != nil {
			return err
		}
		var m Manifest
		if err := json.Unmarshal(raw, &m); err != nil {
			return err
		}
		if m.Snapshot != current {
			return fmt.Errorf("catalog snapshot mismatch")
		}
		if err := v.Verify(m, pub); err != nil {
			return err
		}
		ciphertext, err := os.ReadFile(filepath.Join(v.Root, "snapshots", current))
		if err != nil {
			return err
		}
		h := sha256.Sum256(ciphertext)
		if hex.EncodeToString(h[:]) != current {
			return fmt.Errorf("snapshot hash mismatch")
		}
		if m.Previous == "" {
			return nil
		}
		current = m.Previous
	}
	return nil
}

func (v *Vault) VerifyCurrentHead(candidate string) error {
	if candidate == "" || candidate != v.Head {
		return fmt.Errorf("catalog rollback detected")
	}
	return nil
}
func (v *Vault) VerifySnapshot(m Manifest, ciphertext []byte, pub ed25519.PublicKey) error {
	if err := v.Verify(m, pub); err != nil {
		return err
	}
	h := sha256.Sum256(ciphertext)
	if hex.EncodeToString(h[:]) != m.Snapshot {
		return fmt.Errorf("snapshot hash mismatch")
	}
	return nil
}

func (v *Vault) Load(id string) ([]Record, error) {
	if id == "" || filepath.Base(id) != id {
		return nil, fmt.Errorf("invalid snapshot id")
	}
	raw, err := os.ReadFile(filepath.Join(v.Root, "snapshots", id))
	if err != nil {
		return nil, err
	}
	plain, err := crypt.Open(raw, v.Operational)
	if err != nil {
		return nil, err
	}
	var records []Record
	if err := json.Unmarshal(plain, &records); err != nil {
		return nil, err
	}
	return records, nil
}
func (v *Vault) RecordsFromCiphertext(ciphertext []byte) ([]Record, error) {
	plain, err := crypt.Open(ciphertext, v.Operational)
	if err != nil {
		return nil, err
	}
	var records []Record
	if err := json.Unmarshal(plain, &records); err != nil {
		return nil, err
	}
	return records, nil
}

// Restore stages the complete tree first. Existing files are moved to a backup
// directory before staged files are activated; on an activation error the
// already moved files are put back.
func Restore(records []Record, target, backupRoot string) error {
	if filepath.Clean(target) == "." || filepath.Clean(target) == "/" {
		return fmt.Errorf("unsafe restore target")
	}
	stage, err := os.MkdirTemp(filepath.Dir(target), ".cifrarium-restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for _, r := range records {
		if r.Path == "" || filepath.IsAbs(r.Path) || filepath.Clean(r.Path) != r.Path || r.Path == "." || filepath.Base(r.Path) == ".." || r.Path == ".." || strings.HasPrefix(r.Path, ".."+string(filepath.Separator)) {
			return fmt.Errorf("unsafe restore path %q", r.Path)
		}
		p := filepath.Join(stage, r.Path)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(p, r.Data, os.FileMode(r.Mode)&0777); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(backupRoot, 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(target, 0700); err != nil {
		return err
	}
	backup, err := os.MkdirTemp(backupRoot, "restore-")
	if err != nil {
		return err
	}
	var moved []struct{ from, to string }
	rollback := func() {
		for i := len(moved) - 1; i >= 0; i-- {
			_ = os.MkdirAll(filepath.Dir(moved[i].from), 0700)
			_ = os.Rename(moved[i].to, moved[i].from)
		}
	}
	err = filepath.Walk(stage, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == stage || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(stage, path)
		dest := filepath.Join(target, rel)
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("staged symlink rejected")
		}
		if old, e := os.Lstat(dest); e == nil {
			if old.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("target symlink rejected: %s", rel)
			}
			b := filepath.Join(backup, rel)
			if e = os.MkdirAll(filepath.Dir(b), 0700); e != nil {
				return e
			}
			if e = os.Rename(dest, b); e != nil {
				return e
			}
			moved = append(moved, struct{ from, to string }{dest, b})
		} else if !os.IsNotExist(e) {
			return e
		}
		if e := os.MkdirAll(filepath.Dir(dest), 0700); e != nil {
			return e
		}
		if e := os.Rename(path, dest); e != nil {
			return e
		}
		return nil
	})
	if err != nil {
		rollback()
		return err
	}
	return nil
}
func manifestBytes(m Manifest) []byte { m.Signature = ""; b, _ := json.Marshal(m); return b }
func sortRecords(r []Record) {
	for i := range r {
		for j := i + 1; j < len(r); j++ {
			if r[j].Path < r[i].Path {
				r[i], r[j] = r[j], r[i]
			}
		}
	}
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".cifrarium-write-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
