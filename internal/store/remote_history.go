package store

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/teelabs/cifrarium/internal/limits"
)

var ErrRemoteHistoryForked = errors.New("remote snapshot history is forked or has no unique head")
var ErrRemoteSnapshotCatalog = errors.New("remote snapshot catalog is invalid")
var ErrRemoteSnapshotIntegrity = errors.New("remote snapshot integrity verification failed")
var ErrRemoteSnapshotDecryption = errors.New("remote snapshot decryption failed")

const (
	maxRemoteHistorySnapshots = 1024
	maxRemoteHistoryBytes     = 512 << 20
)

type RemoteSnapshot struct {
	ID         string
	Ciphertext []byte
	Catalog    []byte
}

type VerifiedSnapshot struct {
	ID         string
	Manifest   Manifest
	Records    []Record
	Ciphertext []byte
	Catalog    []byte
}

type VerifiedHistory struct {
	Head     string
	Entries  []VerifiedSnapshot // newest first
	verified bool
}

// RemoteHistoryInspection contains one fully verified lineage for every tip
// in the remote object set. Branches are sorted by head identifier.
type RemoteHistoryInspection struct {
	Branches []VerifiedHistory
}

// MissingHistorySnapshotsError reports encrypted snapshot IDs referenced by a
// verified catalog but absent from the supplied remote object set. IDs are
// available only to internal recovery code; Error intentionally stays generic.
type MissingHistorySnapshotsError struct {
	SnapshotIDs []string
}

func (e *MissingHistorySnapshotsError) Error() string {
	return "remote snapshot chain is incomplete"
}

// RemoteSnapshotResolver loads one specifically requested, previously absent
// ancestor. The returned boolean is false when the provider cannot supply it.
type RemoteSnapshotResolver func(id string) (RemoteSnapshot, bool, error)

// InspectRemoteHistory verifies every complete lineage in a remote object set.
// Shared ancestors are retained in each branch; no branch is chosen implicitly.
func InspectRemoteHistory(remote []RemoteSnapshot, operational []byte, signing ed25519.PrivateKey) (RemoteHistoryInspection, error) {
	return InspectRemoteHistoryWithResolver(remote, operational, signing, nil)
}

// InspectRemoteHistoryWithResolver verifies each supplied snapshot once and
// resolves only missing ancestors as the graph traversal reaches them.
func InspectRemoteHistoryWithResolver(remote []RemoteSnapshot, operational []byte, signing ed25519.PrivateKey, resolve RemoteSnapshotResolver) (RemoteHistoryInspection, error) {
	if len(remote) == 0 || len(remote) > maxRemoteHistorySnapshots || len(operational) != 32 || len(signing) != ed25519.PrivateKeySize {
		return RemoteHistoryInspection{}, fmt.Errorf("remote snapshot history is empty or exceeds the supported limit")
	}
	items := make(map[string]VerifiedSnapshot, len(remote))
	manifests := make(map[string]Manifest, len(remote))
	children := make(map[string]bool, len(remote))
	vault := New("", operational, signing)
	public := signing.Public().(ed25519.PublicKey)
	var total int64
	addSnapshot := func(item RemoteSnapshot) error {
		if err := checkRemoteHistorySnapshotCount(len(items)); err != nil {
			return err
		}
		if !validHistorySnapshotID(item.ID) {
			return fmt.Errorf("remote provider contains an invalid snapshot identifier")
		}
		if _, ok := items[item.ID]; ok {
			return fmt.Errorf("remote provider contains duplicate snapshot identifiers")
		}
		if err := limits.CheckBytes(len(item.Ciphertext), limits.MaxSnapshotCipherBytes); err != nil {
			return err
		}
		if err := limits.CheckBytes(len(item.Catalog), limits.MaxManifestBytes); err != nil {
			return err
		}
		if total > maxRemoteHistoryBytes-int64(len(item.Ciphertext))-int64(len(item.Catalog)) {
			return fmt.Errorf("remote snapshot history exceeds the recovery size limit")
		}
		manifest, err := OpenManifest(item.Catalog, operational)
		if err != nil || manifest.Snapshot != item.ID {
			return fmt.Errorf("remote snapshot catalog is invalid: %w", ErrRemoteSnapshotCatalog)
		}
		if err := vault.VerifySnapshot(manifest, item.Ciphertext, public); err != nil {
			return fmt.Errorf("remote snapshot signature or hash verification failed: %w", ErrRemoteSnapshotIntegrity)
		}
		records, err := vault.RecordsFromCiphertext(item.Ciphertext)
		if err != nil {
			return fmt.Errorf("remote snapshot decryption failed: %w", ErrRemoteSnapshotDecryption)
		}
		if manifest.Previous != "" {
			if !validHistorySnapshotID(manifest.Previous) {
				return fmt.Errorf("remote snapshot chain contains an invalid link")
			}
			children[manifest.Previous] = true
		}
		total += int64(len(item.Ciphertext)) + int64(len(item.Catalog))
		items[item.ID] = VerifiedSnapshot{ID: item.ID, Manifest: manifest, Records: records, Ciphertext: append([]byte(nil), item.Ciphertext...), Catalog: append([]byte(nil), item.Catalog...)}
		manifests[item.ID] = manifest
		return nil
	}
	for _, item := range remote {
		if err := addSnapshot(item); err != nil {
			return RemoteHistoryInspection{}, err
		}
	}
	var heads []string
	for id := range items {
		if !children[id] {
			heads = append(heads, id)
		}
	}
	sort.Strings(heads)
	if len(heads) == 0 {
		return RemoteHistoryInspection{}, fmt.Errorf("remote snapshot history contains a loop")
	}
	inspection := RemoteHistoryInspection{Branches: make([]VerifiedHistory, 0, len(heads))}
	covered := make(map[string]bool, len(items))
	missing := make(map[string]struct{})
	for _, head := range heads {
		branch := VerifiedHistory{Head: head, Entries: make([]VerifiedSnapshot, 0), verified: true}
		seen := make(map[string]bool)
		for current := head; current != ""; current = manifests[current].Previous {
			if seen[current] {
				return RemoteHistoryInspection{}, fmt.Errorf("remote snapshot chain contains a loop")
			}
			item, ok := items[current]
			if !ok {
				if resolve == nil {
					missing[current] = struct{}{}
					break
				}
				resolved, found, err := resolve(current)
				if err != nil {
					return RemoteHistoryInspection{}, err
				}
				if !found {
					missing[current] = struct{}{}
					break
				}
				if resolved.ID != current {
					return RemoteHistoryInspection{}, fmt.Errorf("remote history resolver returned the wrong snapshot")
				}
				if err := addSnapshot(resolved); err != nil {
					return RemoteHistoryInspection{}, err
				}
				item = items[current]
			}
			seen[current], covered[current] = true, true
			branch.Entries = append(branch.Entries, item)
		}
		inspection.Branches = append(inspection.Branches, branch)
	}
	if len(missing) > 0 {
		ids := make([]string, 0, len(missing))
		for id := range missing {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		return RemoteHistoryInspection{}, &MissingHistorySnapshotsError{SnapshotIDs: ids}
	}
	if len(covered) != len(items) {
		return RemoteHistoryInspection{}, fmt.Errorf("remote snapshot history contains disconnected branches")
	}
	return inspection, nil
}

func checkRemoteHistorySnapshotCount(count int) error {
	if count >= maxRemoteHistorySnapshots {
		return fmt.Errorf("remote snapshot history exceeds the supported limit")
	}
	return nil
}

// VerifyRemoteHistory keeps the legacy single-chain contract and fails closed
// when more than one verified tip exists.
func VerifyRemoteHistory(remote []RemoteSnapshot, operational []byte, signing ed25519.PrivateKey) (VerifiedHistory, error) {
	return VerifyRemoteHistoryWithResolver(remote, operational, signing, nil)
}

// VerifyRemoteHistoryWithResolver preserves the unique-head contract while
// resolving required ancestors during the same verification traversal.
func VerifyRemoteHistoryWithResolver(remote []RemoteSnapshot, operational []byte, signing ed25519.PrivateKey, resolve RemoteSnapshotResolver) (VerifiedHistory, error) {
	inspection, err := InspectRemoteHistoryWithResolver(remote, operational, signing, resolve)
	if err != nil {
		return VerifiedHistory{}, err
	}
	if len(inspection.Branches) != 1 {
		return VerifiedHistory{}, ErrRemoteHistoryForked
	}
	return inspection.Branches[0], nil
}

// VerifyRemoteHistoryWithSelection uses an authenticated encrypted marker to
// select a branch. Without a marker, only a unique branch is accepted.
func VerifyRemoteHistoryWithSelection(remote []RemoteSnapshot, marker, operational []byte, signing ed25519.PrivateKey) (VerifiedHistory, error) {
	return VerifyRemoteHistoryWithSelectionResolver(remote, marker, operational, signing, nil)
}

// VerifyRemoteHistoryWithSelectionResolver authenticates the selection marker
// after verifying each history entry once, including lazily recovered ancestors.
func VerifyRemoteHistoryWithSelectionResolver(remote []RemoteSnapshot, marker, operational []byte, signing ed25519.PrivateKey, resolve RemoteSnapshotResolver) (VerifiedHistory, error) {
	if len(marker) == 0 {
		return VerifyRemoteHistoryWithResolver(remote, operational, signing, resolve)
	}
	inspection, err := InspectRemoteHistoryWithResolver(remote, operational, signing, resolve)
	if err != nil {
		return VerifiedHistory{}, err
	}
	selection, err := OpenHistorySelection(marker, operational, signing.Public().(ed25519.PublicKey))
	if err != nil {
		return VerifiedHistory{}, ErrInvalidHistorySelection
	}
	for _, branch := range inspection.Branches {
		if branch.Head == selection.Head {
			return branch, nil
		}
	}
	return VerifiedHistory{}, ErrInvalidHistorySelection
}

// InstallVerifiedHistory copies a verified remote chain into the local vault.
// An existing local head must already be an ancestor of the remote head.
func InstallVerifiedHistory(root string, history VerifiedHistory, operational []byte, signing ed25519.PrivateKey, guard HeadGuard) error {
	return InstallVerifiedHistoryWithCommit(root, history, operational, signing, guard, nil)
}

// InstallVerifiedHistoryWithCommit keeps its file and head-guard rollback
// available until the caller's final local validation has succeeded.
func InstallVerifiedHistoryWithCommit(root string, history VerifiedHistory, operational []byte, signing ed25519.PrivateKey, guard HeadGuard, commit func() error) error {
	cloned, err := cloneVerifiedHistory(history)
	if err != nil {
		return err
	}
	history = cloned
	if !history.verified || history.Head == "" || len(history.Entries) == 0 || history.Entries[0].ID != history.Head {
		return fmt.Errorf("remote snapshot history was not verified")
	}
	return withVaultLock(root, func() error {
		return installVerifiedHistoryWithCommitLocked(root, history, operational, signing, guard, commit)
	})
}

// InstallVerifiedHistoryWithCommitUnderLock is for callers that already hold
// the vault recovery lock for a larger restore transaction.
func InstallVerifiedHistoryWithCommitUnderLock(root string, history VerifiedHistory, operational []byte, signing ed25519.PrivateKey, guard HeadGuard, commit func() error) error {
	cloned, err := cloneVerifiedHistory(history)
	if err != nil {
		return err
	}
	history = cloned
	return installVerifiedHistoryWithCommitLocked(root, history, operational, signing, guard, commit)
}

func installVerifiedHistoryWithCommitLocked(root string, history VerifiedHistory, operational []byte, signing ed25519.PrivateKey, guard HeadGuard, commit func() error) error {
	if !history.verified || history.Head == "" || len(history.Entries) == 0 || history.Entries[0].ID != history.Head {
		return fmt.Errorf("remote snapshot history was not verified")
	}
	if err := validateVerifiedHistoryContents(history, operational, signing); err != nil {
		return err
	}
	if err := ValidateRoot(root); err != nil {
		return err
	}
	chainIDs := make(map[string]bool, len(history.Entries))
	for _, entry := range history.Entries {
		if !validHistorySnapshotID(entry.ID) || chainIDs[entry.ID] {
			return fmt.Errorf("invalid verified snapshot history")
		}
		chainIDs[entry.ID] = true
	}
	previousHead := ""
	if guard != nil {
		value, err := guard.CatalogHead()
		if err != nil {
			return err
		}
		previousHead = value
		if previousHead != "" && !chainIDs[previousHead] {
			return fmt.Errorf("remote snapshot history does not contain the guarded local head")
		}
	}
	vault := New(root, operational, signing)
	if localHead, err := vault.LoadHead(); err == nil {
		if !chainIDs[localHead.Snapshot] {
			return fmt.Errorf("remote snapshot history does not extend the local vault")
		}
		if err := vault.VerifyChain(localHead.Snapshot, signing.Public().(ed25519.PublicKey)); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	paths := []string{filepath.Join(root, "head.json")}
	for _, entry := range history.Entries {
		paths = append(paths, filepath.Join(root, "snapshots", entry.ID), filepath.Join(root, "catalog", entry.ID+".json"))
	}
	for _, path := range paths {
		if err := rejectSymlinkPath(path); err != nil {
			return err
		}
	}
	previousFiles, err := captureFileStates(paths...)
	if err != nil {
		return err
	}
	guardUpdateAttempted := false
	rollback := func(cause error) error {
		rollbackErr := restoreFileStates(previousFiles)
		if guard != nil && guardUpdateAttempted {
			if err := guard.SetCatalogHead(previousHead); rollbackErr == nil {
				rollbackErr = err
			}
		}
		if rollbackErr != nil {
			return fmt.Errorf("%w; remote history rollback failed: %v", cause, rollbackErr)
		}
		return cause
	}
	for _, entry := range history.Entries {
		for _, object := range []struct {
			path string
			data []byte
		}{
			{filepath.Join(root, "snapshots", entry.ID), entry.Ciphertext},
			{filepath.Join(root, "catalog", entry.ID+".json"), entry.Catalog},
		} {
			if err := os.MkdirAll(filepath.Dir(object.path), 0700); err != nil {
				return rollback(err)
			}
			if current, err := readLimitedFile(object.path, limits.MaxSnapshotCipherBytes); err == nil {
				if !bytes.Equal(current, object.data) {
					return rollback(fmt.Errorf("local snapshot object differs from verified history"))
				}
				continue
			} else if !os.IsNotExist(err) {
				return rollback(err)
			}
			if err := writeAtomic(object.path, object.data, 0600); err != nil {
				return rollback(err)
			}
		}
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return rollback(err)
	}
	if err := writeAtomic(filepath.Join(root, "head.json"), history.Entries[0].Catalog, 0600); err != nil {
		return rollback(err)
	}
	if guard != nil {
		guardUpdateAttempted = true
		if err := guard.SetCatalogHead(history.Head); err != nil {
			return rollback(err)
		}
	}
	if commit != nil {
		if err := commit(); err != nil {
			return rollback(err)
		}
	}
	return nil
}

func cloneVerifiedHistory(history VerifiedHistory) (VerifiedHistory, error) {
	if !history.verified || history.Head == "" || len(history.Entries) == 0 || len(history.Entries) > maxRemoteHistorySnapshots || history.Entries[0].ID != history.Head {
		return VerifiedHistory{}, fmt.Errorf("invalid verified snapshot history")
	}
	cloned := VerifiedHistory{Head: history.Head, verified: history.verified, Entries: make([]VerifiedSnapshot, len(history.Entries))}
	var total, recordsTotal int64
	seen := make(map[string]bool, len(history.Entries))
	for i, entry := range history.Entries {
		if !validHistorySnapshotID(entry.ID) || seen[entry.ID] || entry.ID != entry.Manifest.Snapshot {
			return VerifiedHistory{}, fmt.Errorf("invalid verified snapshot history")
		}
		seen[entry.ID] = true
		wantPrevious := ""
		if i+1 < len(history.Entries) {
			wantPrevious = history.Entries[i+1].ID
		}
		if entry.Manifest.Previous != wantPrevious {
			return VerifiedHistory{}, fmt.Errorf("verified snapshot history is not a complete linear chain")
		}
		if err := limits.CheckBytes(len(entry.Ciphertext), limits.MaxSnapshotCipherBytes); err != nil {
			return VerifiedHistory{}, err
		}
		if err := limits.CheckBytes(len(entry.Catalog), limits.MaxManifestBytes); err != nil {
			return VerifiedHistory{}, err
		}
		if err := validateRecords(entry.Records); err != nil {
			return VerifiedHistory{}, err
		}
		for _, record := range entry.Records {
			recordsTotal += int64(len(record.Path)) + int64(len(record.Data))
		}
		if recordsTotal > maxRemoteHistoryBytes {
			return VerifiedHistory{}, fmt.Errorf("remote snapshot history exceeds the recovery size limit")
		}
		total += int64(len(entry.Ciphertext)) + int64(len(entry.Catalog))
		if total > maxRemoteHistoryBytes {
			return VerifiedHistory{}, fmt.Errorf("remote snapshot history exceeds the recovery size limit")
		}
		entry.Ciphertext = append([]byte(nil), entry.Ciphertext...)
		entry.Catalog = append([]byte(nil), entry.Catalog...)
		entry.Records = append([]Record(nil), entry.Records...)
		for j := range entry.Records {
			entry.Records[j].Data = append([]byte(nil), entry.Records[j].Data...)
		}
		if entry.Manifest.Metadata != nil {
			metadata := *entry.Manifest.Metadata
			entry.Manifest.Metadata = &metadata
		}
		cloned.Entries[i] = entry
	}
	return cloned, nil
}

func validateVerifiedHistoryContents(history VerifiedHistory, operational []byte, signing ed25519.PrivateKey) error {
	if len(history.Entries) > maxRemoteHistorySnapshots || len(operational) != 32 || len(signing) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid verified snapshot history")
	}
	vault := New("", operational, signing)
	public := signing.Public().(ed25519.PublicKey)
	seen := make(map[string]bool, len(history.Entries))
	for i, entry := range history.Entries {
		if !validHistorySnapshotID(entry.ID) || seen[entry.ID] || entry.ID != entry.Manifest.Snapshot {
			return fmt.Errorf("invalid verified snapshot history")
		}
		seen[entry.ID] = true
		manifest, err := OpenManifest(entry.Catalog, operational)
		if err != nil || !reflect.DeepEqual(manifest, entry.Manifest) {
			return fmt.Errorf("verified snapshot catalog was modified")
		}
		wantPrevious := ""
		if i+1 < len(history.Entries) {
			wantPrevious = history.Entries[i+1].ID
		}
		if manifest.Previous != wantPrevious {
			return fmt.Errorf("verified snapshot history is not a complete linear chain")
		}
		if err := vault.VerifySnapshot(manifest, entry.Ciphertext, public); err != nil {
			return fmt.Errorf("verified snapshot content was modified")
		}
		records, err := vault.RecordsFromCiphertext(entry.Ciphertext)
		if err != nil || !reflect.DeepEqual(records, entry.Records) {
			return fmt.Errorf("verified snapshot records were modified")
		}
	}
	return nil
}

func validHistorySnapshotID(id string) bool {
	if len(id) != 64 || strings.ToLower(id) != id {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}
