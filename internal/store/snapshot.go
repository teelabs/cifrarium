package store

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	crypt "github.com/teelabs/cifrarium/internal/crypto"
	"github.com/teelabs/cifrarium/internal/limits"
)

type Record struct {
	Path string `json:"path"`
	Mode uint32 `json:"mode"`
	Data []byte `json:"data"`
}
type Manifest struct {
	Version   int               `json:"version"`
	CreatedAt time.Time         `json:"created_at"`
	Previous  string            `json:"previous"`
	Snapshot  string            `json:"snapshot"`
	Signer    string            `json:"signer"`
	Signature string            `json:"signature"`
	Metadata  *SnapshotMetadata `json:"metadata,omitempty"`
}
type SnapshotMetadata struct {
	Version            int    `json:"version"`
	ContentFingerprint string `json:"content_fingerprint"`
	Signature          string `json:"signature"`
}
type SnapshotResult struct {
	Manifest      Manifest
	Ciphertext    []byte
	ManifestBytes []byte
	Unchanged     bool
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
	if err := ValidateRoot(root); err != nil {
		return nil, fmt.Errorf("validate vault root: %w", err)
	}
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
	plain, fingerprint, err := prepareRecords(records, v.Operational)
	if err != nil {
		return Manifest{}, err
	}
	var result SnapshotResult
	err = withVaultLock(v.Root, func() error {
		if err := v.reloadHeadLocked(); err != nil {
			return err
		}
		var saveErr error
		result, saveErr = v.saveUnlocked(plain, fingerprint)
		return saveErr
	})
	return result.Manifest, err
}

// SaveIfChanged atomically compares canonical captured records with the current
// verified head and saves only when their authenticated fingerprints differ.
// The unchanged result contains the exact persisted ciphertext and encrypted
// catalog bytes so an uploader can safely repair a missing remote copy.
func (v *Vault) SaveIfChanged(records []Record) (SnapshotResult, error) {
	plain, fingerprint, err := prepareRecords(records, v.Operational)
	if err != nil {
		return SnapshotResult{}, err
	}
	var result SnapshotResult
	err = withVaultLock(v.Root, func() error {
		if err := v.reloadHeadLocked(); err != nil {
			return err
		}
		if v.Head != "" {
			current, ciphertext, manifestBytes, err := v.currentSnapshotLocked()
			if err != nil {
				return err
			}
			currentFingerprint := ""
			if current.Metadata != nil {
				currentFingerprint = current.Metadata.ContentFingerprint
			} else {
				previousRecords, err := v.RecordsFromCiphertext(ciphertext)
				if err != nil {
					return fmt.Errorf("read legacy snapshot for comparison: %w", err)
				}
				previousPlain, _, err := prepareRecords(previousRecords, v.Operational)
				if err != nil {
					return fmt.Errorf("prepare legacy snapshot for comparison: %w", err)
				}
				currentFingerprint, err = contentFingerprint(previousPlain, v.Operational)
				if err != nil {
					return err
				}
			}
			if hmac.Equal([]byte(currentFingerprint), []byte(fingerprint)) {
				result = SnapshotResult{Manifest: current, Ciphertext: ciphertext, ManifestBytes: manifestBytes, Unchanged: true}
				return nil
			}
		}
		var saveErr error
		result, saveErr = v.saveUnlocked(plain, fingerprint)
		return saveErr
	})
	return result, err
}

func prepareRecords(records []Record, operationalKey []byte) ([]byte, string, error) {
	if err := validateRecords(records); err != nil {
		return nil, "", err
	}
	sortRecords(records)
	plain, err := json.Marshal(records)
	if err != nil {
		return nil, "", err
	}
	if err := limits.CheckBytes(len(plain), limits.MaxSnapshotPlainBytes); err != nil {
		return nil, "", err
	}
	fingerprint, err := contentFingerprint(plain, operationalKey)
	if err != nil {
		return nil, "", err
	}
	return plain, fingerprint, nil
}

func contentFingerprint(plain, operationalKey []byte) (string, error) {
	if len(operationalKey) != 32 {
		return "", fmt.Errorf("operational key must be 32 bytes")
	}
	keyMAC := hmac.New(sha256.New, operationalKey)
	_, _ = keyMAC.Write([]byte("cifrarium/snapshot-content-fingerprint/v1"))
	derivedKey := keyMAC.Sum(nil)
	contentMAC := hmac.New(sha256.New, derivedKey)
	_, _ = contentMAC.Write(plain)
	return hex.EncodeToString(contentMAC.Sum(nil)), nil
}

func (v *Vault) saveUnlocked(plain []byte, fingerprint string) (SnapshotResult, error) {
	if err := os.MkdirAll(v.Root, 0700); err != nil {
		return SnapshotResult{}, err
	}
	ciphertext, err := crypt.Seal(plain, v.Operational)
	if err != nil {
		return SnapshotResult{}, err
	}
	if err := limits.CheckBytes(len(ciphertext), limits.MaxSnapshotCipherBytes); err != nil {
		return SnapshotResult{}, err
	}
	h := sha256.Sum256(ciphertext)
	sum := hex.EncodeToString(h[:])
	m := Manifest{Version: 1, CreatedAt: time.Now().UTC(), Previous: v.Head, Snapshot: sum, Signer: crypt.Fingerprint(v.Signing.Public().(ed25519.PublicKey))}
	m.Metadata = &SnapshotMetadata{Version: 1, ContentFingerprint: fingerprint}
	m.Signature = hex.EncodeToString(ed25519.Sign(v.Signing, manifestBytes(m)))
	m.Metadata.Signature = hex.EncodeToString(ed25519.Sign(v.Signing, metadataBytes(m)))
	dir := filepath.Join(v.Root, "snapshots")
	if err = os.MkdirAll(dir, 0700); err != nil {
		return SnapshotResult{}, err
	}
	b, err := SealManifest(m, v.Operational)
	if err != nil {
		return SnapshotResult{}, err
	}
	snapshotPath := filepath.Join(v.Root, "snapshots", sum)
	catalogPath := filepath.Join(v.Root, "catalog", sum+".json")
	headPath := filepath.Join(v.Root, "head.json")
	previousFiles, err := captureFileStates(snapshotPath, catalogPath, headPath)
	if err != nil {
		return SnapshotResult{}, err
	}
	previousGuardHead := ""
	if v.Guard != nil {
		previousGuardHead, err = v.Guard.CatalogHead()
		if err != nil {
			return SnapshotResult{}, err
		}
	}
	guardUpdateAttempted := false
	rollback := func(cause error) (SnapshotResult, error) {
		rollbackErr := restoreFileStates(previousFiles)
		if v.Guard != nil && guardUpdateAttempted {
			if guardErr := v.Guard.SetCatalogHead(previousGuardHead); rollbackErr == nil {
				rollbackErr = guardErr
			}
		}
		if rollbackErr != nil {
			return SnapshotResult{}, fmt.Errorf("%w; snapshot rollback failed: %v", cause, rollbackErr)
		}
		return SnapshotResult{}, cause
	}
	if err = writeAtomic(snapshotPath, ciphertext, 0600); err != nil {
		return rollback(err)
	}
	if err = writeAtomic(catalogPath, b, 0600); err != nil {
		return rollback(err)
	}
	if err = writeAtomic(headPath, b, 0600); err != nil {
		return rollback(err)
	}
	if v.Guard != nil {
		guardUpdateAttempted = true
		if err := v.Guard.SetCatalogHead(m.Snapshot); err != nil {
			return rollback(err)
		}
	}
	v.Head = sum
	return SnapshotResult{Manifest: m, Ciphertext: ciphertext, ManifestBytes: b}, nil
}

func (v *Vault) reloadHeadLocked() error {
	rawHead, err := readLimitedFile(filepath.Join(v.Root, "head.json"), limits.MaxManifestBytes)
	if os.IsNotExist(err) {
		if v.Guard != nil {
			guardHead, guardErr := v.Guard.CatalogHead()
			if guardErr != nil {
				return guardErr
			}
			if guardHead != "" {
				return fmt.Errorf("catalog head missing while keyring guard is set")
			}
		}
		v.Head = ""
		return nil
	}
	if err != nil {
		return err
	}
	manifest, err := OpenManifest(rawHead, v.Operational)
	if err != nil {
		return err
	}
	if manifest.Snapshot == "" || filepath.Base(manifest.Snapshot) != manifest.Snapshot {
		return fmt.Errorf("invalid catalog head")
	}
	rawCatalog, err := readLimitedFile(filepath.Join(v.Root, "catalog", manifest.Snapshot+".json"), limits.MaxManifestBytes)
	if err != nil {
		return err
	}
	if !bytes.Equal(rawHead, rawCatalog) {
		return fmt.Errorf("catalog head does not match current catalog entry")
	}
	if v.Guard != nil {
		guardHead, guardErr := v.Guard.CatalogHead()
		if guardErr != nil {
			return guardErr
		}
		if guardHead != manifest.Snapshot {
			return fmt.Errorf("catalog rollback detected")
		}
	}
	if v.Head != manifest.Snapshot {
		if err := v.VerifyChain(manifest.Snapshot, v.Signing.Public().(ed25519.PublicKey)); err != nil {
			return err
		}
	}
	ciphertext, err := readLimitedFile(filepath.Join(v.Root, "snapshots", manifest.Snapshot), limits.MaxSnapshotCipherBytes)
	if err != nil {
		return err
	}
	if err := v.VerifySnapshot(manifest, ciphertext, v.Signing.Public().(ed25519.PublicKey)); err != nil {
		return err
	}
	v.Head = manifest.Snapshot
	return nil
}

func (v *Vault) currentSnapshotLocked() (Manifest, []byte, []byte, error) {
	rawManifest, err := readLimitedFile(filepath.Join(v.Root, "catalog", v.Head+".json"), limits.MaxManifestBytes)
	if err != nil {
		return Manifest{}, nil, nil, err
	}
	manifest, err := OpenManifest(rawManifest, v.Operational)
	if err != nil {
		return Manifest{}, nil, nil, err
	}
	if manifest.Snapshot != v.Head {
		return Manifest{}, nil, nil, fmt.Errorf("catalog snapshot mismatch")
	}
	ciphertext, err := readLimitedFile(filepath.Join(v.Root, "snapshots", v.Head), limits.MaxSnapshotCipherBytes)
	if err != nil {
		return Manifest{}, nil, nil, err
	}
	return manifest, ciphertext, rawManifest, nil
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
	if m.Metadata != nil {
		if m.Metadata.Version != 1 {
			return fmt.Errorf("unsupported snapshot metadata version")
		}
		fingerprint, err := hex.DecodeString(m.Metadata.ContentFingerprint)
		if err != nil || len(fingerprint) != sha256.Size || hex.EncodeToString(fingerprint) != m.Metadata.ContentFingerprint {
			return fmt.Errorf("invalid snapshot content fingerprint")
		}
		metadataSignature, err := hex.DecodeString(m.Metadata.Signature)
		if err != nil || !ed25519.Verify(pub, metadataBytes(m), metadataSignature) {
			return fmt.Errorf("invalid snapshot metadata signature")
		}
	}
	return nil
}

func (v *Vault) LoadHead() (Manifest, error) {
	raw, err := readLimitedFile(filepath.Join(v.Root, "head.json"), limits.MaxManifestBytes)
	if err != nil {
		return Manifest{}, err
	}
	return OpenManifest(raw, v.Operational)
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
		raw, err := readLimitedFile(filepath.Join(v.Root, "catalog", current+".json"), limits.MaxManifestBytes)
		if err != nil {
			return err
		}
		m, err := OpenManifest(raw, v.Operational)
		if err != nil {
			return err
		}
		if m.Snapshot != current {
			return fmt.Errorf("catalog snapshot mismatch")
		}
		if err := v.Verify(m, pub); err != nil {
			return err
		}
		ciphertext, err := readLimitedFile(filepath.Join(v.Root, "snapshots", current), limits.MaxSnapshotCipherBytes)
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

// VerifyHistoricalHead permits an explicit restore of a snapshot that is
// already anchored in the verified local catalog chain. It never changes the
// active head, so selecting history cannot roll the vault's write head back.
func (v *Vault) VerifyHistoricalHead(candidate string, pub ed25519.PublicKey) error {
	if candidate == "" || filepath.Base(candidate) != candidate {
		return fmt.Errorf("invalid catalog snapshot")
	}
	if v.Head == "" {
		return fmt.Errorf("catalog has no active head")
	}
	if err := v.VerifyChain(v.Head, pub); err != nil {
		return err
	}
	for current, depth := v.Head, 0; current != ""; depth++ {
		if depth > 1024 {
			return fmt.Errorf("catalog chain too deep")
		}
		if current == candidate {
			return nil
		}
		raw, err := readLimitedFile(filepath.Join(v.Root, "catalog", current+".json"), limits.MaxManifestBytes)
		if err != nil {
			return err
		}
		m, err := OpenManifest(raw, v.Operational)
		if err != nil {
			return err
		}
		current = m.Previous
	}
	return fmt.Errorf("historical snapshot is not in the active catalog chain")
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

// SealManifest keeps catalog metadata encrypted at rest and in providers.
// The signature is computed over the plaintext manifest before sealing so a
// verifier can authenticate it after decrypting with the operational key.
func SealManifest(m Manifest, operationalKey []byte) ([]byte, error) {
	plain, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	if err := limits.CheckBytes(len(plain), limits.MaxManifestBytes); err != nil {
		return nil, err
	}
	return crypt.Seal(plain, operationalKey)
}

func OpenManifest(raw, operationalKey []byte) (Manifest, error) {
	if err := limits.CheckBytes(len(raw), limits.MaxManifestBytes); err != nil {
		return Manifest{}, err
	}
	plain, err := crypt.Open(raw, operationalKey)
	if err != nil {
		return Manifest{}, err
	}
	if err := limits.CheckBytes(len(plain), limits.MaxManifestBytes); err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(plain, &m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// MigrateCatalog converts the pre-encryption plaintext catalog format after
// verifying the complete chain and every referenced ciphertext. It returns
// true when files were rewritten. No plaintext fallback is used by normal
// vault opening.
func MigrateCatalog(root string, operationalKey []byte, pub ed25519.PublicKey) (bool, error) {
	return migrateCatalog(root, operationalKey, pub, writeAtomic)
}

type catalogWriter func(path string, data []byte, mode os.FileMode) error

func migrateCatalog(root string, operationalKey []byte, pub ed25519.PublicKey, write catalogWriter) (bool, error) {
	headRaw, err := readLimitedFile(filepath.Join(root, "head.json"), limits.MaxManifestBytes)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err := OpenManifest(headRaw, operationalKey); err == nil {
		return false, nil
	}
	var head Manifest
	if err := json.Unmarshal(headRaw, &head); err != nil {
		return false, fmt.Errorf("legacy catalog head is invalid: %w", err)
	}
	v := New(root, operationalKey, nil)
	var entries []Manifest
	originals := make([][]byte, 0)
	seen := map[string]bool{}
	for current, depth := head.Snapshot, 0; current != ""; depth++ {
		if depth > 1024 || seen[current] || filepath.Base(current) != current {
			return false, fmt.Errorf("legacy catalog chain loop or invalid head")
		}
		seen[current] = true
		raw, err := readLimitedFile(filepath.Join(root, "catalog", current+".json"), limits.MaxManifestBytes)
		if err != nil {
			return false, err
		}
		var m Manifest
		if err := json.Unmarshal(raw, &m); err != nil {
			return false, fmt.Errorf("legacy catalog entry %s is invalid: %w", current, err)
		}
		originals = append(originals, append([]byte(nil), raw...))
		if m.Snapshot != current {
			return false, fmt.Errorf("legacy catalog snapshot mismatch")
		}
		if err := v.Verify(m, pub); err != nil {
			return false, err
		}
		ciphertext, err := readLimitedFile(filepath.Join(root, "snapshots", current), limits.MaxSnapshotCipherBytes)
		if err != nil {
			return false, err
		}
		h := sha256.Sum256(ciphertext)
		if hex.EncodeToString(h[:]) != current {
			return false, fmt.Errorf("legacy snapshot hash mismatch")
		}
		entries = append(entries, m)
		current = m.Previous
	}
	if head.Snapshot == "" || len(entries) == 0 {
		return false, fmt.Errorf("legacy catalog has no head")
	}
	sealed := make([][]byte, len(entries))
	for i, m := range entries {
		sealed[i], err = SealManifest(m, operationalKey)
		if err != nil {
			return false, err
		}
	}
	rollback := func() {
		for i, m := range entries {
			_ = write(filepath.Join(root, "catalog", m.Snapshot+".json"), originals[i], 0600)
		}
		_ = write(filepath.Join(root, "head.json"), headRaw, 0600)
	}
	for i, m := range entries {
		if err := write(filepath.Join(root, "catalog", m.Snapshot+".json"), sealed[i], 0600); err != nil {
			rollback()
			return false, err
		}
	}
	if err := write(filepath.Join(root, "head.json"), sealed[0], 0600); err != nil {
		rollback()
		return false, err
	}
	return true, nil
}

func (v *Vault) Load(id string) ([]Record, error) {
	if id == "" || filepath.Base(id) != id {
		return nil, fmt.Errorf("invalid snapshot id")
	}
	raw, err := readLimitedFile(filepath.Join(v.Root, "snapshots", id), limits.MaxSnapshotCipherBytes)
	if err != nil {
		return nil, err
	}
	if err := limits.CheckBytes(len(raw), limits.MaxSnapshotCipherBytes); err != nil {
		return nil, err
	}
	plain, err := crypt.Open(raw, v.Operational)
	if err != nil {
		return nil, err
	}
	if err := limits.CheckBytes(len(plain), limits.MaxSnapshotPlainBytes); err != nil {
		return nil, err
	}
	var records []Record
	if err := json.Unmarshal(plain, &records); err != nil {
		return nil, err
	}
	if err := validateRecords(records); err != nil {
		return nil, err
	}
	return records, nil
}

// SnapshotCiphertext returns an opaque encrypted snapshot bounded by the same
// limit used by provider and restore ingestion paths.
func (v *Vault) SnapshotCiphertext(id string) ([]byte, error) {
	if id == "" || filepath.Base(id) != id {
		return nil, fmt.Errorf("invalid snapshot id")
	}
	return readLimitedFile(filepath.Join(v.Root, "snapshots", id), limits.MaxSnapshotCipherBytes)
}

func (v *Vault) RecordsFromCiphertext(ciphertext []byte) ([]Record, error) {
	if err := limits.CheckBytes(len(ciphertext), limits.MaxSnapshotCipherBytes); err != nil {
		return nil, err
	}
	plain, err := crypt.Open(ciphertext, v.Operational)
	if err != nil {
		return nil, err
	}
	if err := limits.CheckBytes(len(plain), limits.MaxSnapshotPlainBytes); err != nil {
		return nil, err
	}
	var records []Record
	if err := json.Unmarshal(plain, &records); err != nil {
		return nil, err
	}
	if err := validateRecords(records); err != nil {
		return nil, err
	}
	return records, nil
}

// Restore stages the complete tree first. Existing files are moved to a backup
// directory before staged files are activated; on an activation error the
// already moved files are put back.
type RenameFunc func(oldPath, newPath string) error

func Restore(records []Record, target, backupRoot string) error {
	return restoreSecure(records, target, backupRoot)
}

// RestoreWithRename is the transactional restore implementation with an
// injectable rename seam for deterministic failure-path tests. Production
// callers must use Restore, which uses descriptor-relative Linux operations.
func RestoreWithRename(records []Record, target, backupRoot string, rename RenameFunc) error {
	if rename == nil {
		return fmt.Errorf("rename function is required")
	}
	if err := validateRecords(records); err != nil {
		return err
	}
	if filepath.Clean(target) == "." || filepath.Clean(target) == "/" {
		return fmt.Errorf("unsafe restore target")
	}
	if err := rejectSymlinkPath(target); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(filepath.Dir(target), ".cifrarium-restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for _, r := range records {
		if err := validateRestoreRecordPath(r.Path); err != nil {
			return err
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
	var activated []string
	rollback := func() {
		for i := len(activated) - 1; i >= 0; i-- {
			_ = os.Remove(activated[i])
		}
		for i := len(moved) - 1; i >= 0; i-- {
			_ = os.MkdirAll(filepath.Dir(moved[i].from), 0700)
			_ = rename(moved[i].to, moved[i].from)
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
		if err := rejectSymlinkPath(dest); err != nil {
			return err
		}
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
			if e = rename(dest, b); e != nil {
				return e
			}
			moved = append(moved, struct{ from, to string }{dest, b})
		} else if !os.IsNotExist(e) {
			return e
		}
		if e := os.MkdirAll(filepath.Dir(dest), 0700); e != nil {
			return e
		}
		if e := rename(path, dest); e != nil {
			return e
		}
		activated = append(activated, dest)
		return nil
	})
	if err != nil {
		rollback()
		return err
	}
	return nil
}

func validateRestoreRecordPath(path string) error {
	if path == "" || filepath.IsAbs(path) || filepath.Clean(path) != path || path == "." || filepath.Base(path) == ".." || path == ".." || strings.HasPrefix(path, ".."+string(filepath.Separator)) {
		return fmt.Errorf("unsafe restore path %q", path)
	}
	return nil
}

func validateRecords(records []Record) error {
	if len(records) > limits.MaxCapturedFiles {
		return fmt.Errorf("snapshot contains too many records")
	}
	var total int64
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		if err := validateRestoreRecordPath(record.Path); err != nil {
			return err
		}
		if _, ok := seen[record.Path]; ok {
			return fmt.Errorf("duplicate snapshot path %q", record.Path)
		}
		seen[record.Path] = struct{}{}
		if len(record.Path) > limits.MaxPathBytes || len(strings.Split(record.Path, string(filepath.Separator))) > limits.MaxPathDepth {
			return fmt.Errorf("snapshot path exceeds limits")
		}
		if err := limits.CheckBytes(len(record.Data), limits.MaxCapturedFileBytes); err != nil {
			return err
		}
		total += int64(len(record.Data))
		if total > limits.MaxSnapshotPlainBytes {
			return fmt.Errorf("snapshot exceeds plaintext limit")
		}
	}
	return nil
}

func rejectSymlinkPath(path string) error {
	clean := filepath.Clean(path)
	absolute := filepath.IsAbs(clean)
	current := ""
	if absolute {
		current = string(filepath.Separator)
	}
	components := strings.Split(clean, string(filepath.Separator))
	for _, component := range components {
		if component == "" || component == "." {
			continue
		}
		if current == "" {
			current = component
		} else {
			current = filepath.Join(current, component)
		}
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink path rejected: %s", path)
		}
	}
	return nil
}

func manifestBytes(m Manifest) []byte {
	m.Signature = ""
	m.Metadata = nil
	b, _ := json.Marshal(m)
	return b
}

func metadataBytes(m Manifest) []byte {
	payload := struct {
		Domain             string `json:"domain"`
		Version            int    `json:"version"`
		ContentFingerprint string `json:"content_fingerprint"`
		Snapshot           string `json:"snapshot"`
		Previous           string `json:"previous"`
		Signer             string `json:"signer"`
	}{
		Domain:             "cifrarium/snapshot-metadata/v1",
		Version:            m.Metadata.Version,
		ContentFingerprint: m.Metadata.ContentFingerprint,
		Snapshot:           m.Snapshot,
		Previous:           m.Previous,
		Signer:             m.Signer,
	}
	b, _ := json.Marshal(payload)
	return b
}
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

type fileState struct {
	path   string
	exists bool
	mode   os.FileMode
	data   []byte
}

func captureFileStates(paths ...string) ([]fileState, error) {
	states := make([]fileState, 0, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			states = append(states, fileState{path: path})
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("snapshot path is not a regular file: %s", path)
		}
		data, err := readLimitedFile(path, limits.MaxSnapshotCipherBytes)
		if err != nil {
			return nil, err
		}
		states = append(states, fileState{path: path, exists: true, mode: info.Mode().Perm(), data: data})
	}
	return states, nil
}

func readLimitedFile(path string, max int64) ([]byte, error) {
	f, err := openReadNoSymlinks(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return limits.ReadAll(f, max)
}

func restoreFileStates(states []fileState) error {
	for _, state := range states {
		if !state.exists {
			if err := os.Remove(state.path); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		if err := writeAtomic(state.path, state.data, state.mode); err != nil {
			return err
		}
	}
	return nil
}
