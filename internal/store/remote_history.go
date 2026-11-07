package store

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/teelabs/cifrarium/internal/limits"
)

var ErrRemoteHistoryForked = errors.New("remote snapshot history is forked or has no unique head")

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

// VerifyRemoteHistory validates one complete, linear signed chain before
// returning any decrypted records to the caller.
func VerifyRemoteHistory(remote []RemoteSnapshot, operational []byte, signing ed25519.PrivateKey) (VerifiedHistory, error) {
	if len(remote) == 0 || len(remote) > maxRemoteHistorySnapshots {
		return VerifiedHistory{}, fmt.Errorf("remote snapshot history is empty or exceeds the supported limit")
	}
	objects := make(map[string]RemoteSnapshot, len(remote))
	manifests := make(map[string]Manifest, len(remote))
	previous := make(map[string]bool, len(remote))
	var total int64
	for _, item := range remote {
		if !validHistorySnapshotID(item.ID) {
			return VerifiedHistory{}, fmt.Errorf("remote provider contains an invalid snapshot identifier")
		}
		if _, duplicate := objects[item.ID]; duplicate {
			return VerifiedHistory{}, fmt.Errorf("remote provider contains duplicate snapshot identifiers")
		}
		if err := limits.CheckBytes(len(item.Ciphertext), limits.MaxSnapshotCipherBytes); err != nil {
			return VerifiedHistory{}, err
		}
		if err := limits.CheckBytes(len(item.Catalog), limits.MaxManifestBytes); err != nil {
			return VerifiedHistory{}, err
		}
		if total > maxRemoteHistoryBytes-int64(len(item.Ciphertext))-int64(len(item.Catalog)) {
			return VerifiedHistory{}, fmt.Errorf("remote snapshot history exceeds the recovery size limit")
		}
		total += int64(len(item.Ciphertext)) + int64(len(item.Catalog))
		manifest, err := OpenManifest(item.Catalog, operational)
		if err != nil || manifest.Snapshot != item.ID {
			return VerifiedHistory{}, fmt.Errorf("remote snapshot catalog is invalid")
		}
		if manifest.Previous != "" {
			if !validHistorySnapshotID(manifest.Previous) {
				return VerifiedHistory{}, fmt.Errorf("remote snapshot chain contains an invalid link")
			}
			previous[manifest.Previous] = true
		}
		objects[item.ID] = item
		manifests[item.ID] = manifest
	}
	var heads []string
	for id := range objects {
		if !previous[id] {
			heads = append(heads, id)
		}
	}
	if len(heads) != 1 {
		return VerifiedHistory{}, ErrRemoteHistoryForked
	}
	head := heads[0]
	chain := make([]string, 0, len(objects))
	seen := make(map[string]bool, len(objects))
	for current := head; current != ""; current = manifests[current].Previous {
		if seen[current] || len(chain) >= maxRemoteHistorySnapshots {
			return VerifiedHistory{}, fmt.Errorf("remote snapshot chain contains a loop or exceeds its limit")
		}
		if _, ok := objects[current]; !ok {
			return VerifiedHistory{}, fmt.Errorf("remote snapshot chain is incomplete")
		}
		seen[current] = true
		chain = append(chain, current)
	}
	if len(chain) != len(objects) {
		return VerifiedHistory{}, fmt.Errorf("remote snapshot history contains disconnected branches")
	}
	stage, err := os.MkdirTemp("", "cifrarium-recovery-verify-")
	if err != nil {
		return VerifiedHistory{}, fmt.Errorf("create recovery verification staging area: %w", err)
	}
	defer os.RemoveAll(stage)
	if err := os.Mkdir(filepath.Join(stage, "snapshots"), 0700); err != nil {
		return VerifiedHistory{}, err
	}
	if err := os.Mkdir(filepath.Join(stage, "catalog"), 0700); err != nil {
		return VerifiedHistory{}, err
	}
	for id, item := range objects {
		if err := writeHistoryStageFile(filepath.Join(stage, "snapshots", id), item.Ciphertext); err != nil {
			return VerifiedHistory{}, err
		}
		if err := writeHistoryStageFile(filepath.Join(stage, "catalog", id+".json"), item.Catalog); err != nil {
			return VerifiedHistory{}, err
		}
	}
	if err := writeHistoryStageFile(filepath.Join(stage, "head.json"), objects[head].Catalog); err != nil {
		return VerifiedHistory{}, err
	}
	vault := New(stage, operational, signing)
	if err := vault.VerifyChain(head, signing.Public().(ed25519.PublicKey)); err != nil {
		return VerifiedHistory{}, fmt.Errorf("remote snapshot chain verification failed")
	}
	vault.Head = head
	history := VerifiedHistory{Head: head, Entries: make([]VerifiedSnapshot, 0, len(chain)), verified: true}
	for _, id := range chain {
		records, err := vault.Load(id)
		if err != nil {
			return VerifiedHistory{}, fmt.Errorf("decrypt verified remote snapshot")
		}
		item := objects[id]
		history.Entries = append(history.Entries, VerifiedSnapshot{
			ID: id, Manifest: manifests[id], Records: records,
			Ciphertext: append([]byte(nil), item.Ciphertext...), Catalog: append([]byte(nil), item.Catalog...),
		})
	}
	return history, nil
}

// InstallVerifiedHistory copies a verified remote chain into the local vault.
// An existing local head must already be an ancestor of the remote head.
func InstallVerifiedHistory(root string, history VerifiedHistory, operational []byte, signing ed25519.PrivateKey, guard HeadGuard) error {
	return InstallVerifiedHistoryWithCommit(root, history, operational, signing, guard, nil)
}

// InstallVerifiedHistoryWithCommit keeps its file and head-guard rollback
// available until the caller's final local validation has succeeded.
func InstallVerifiedHistoryWithCommit(root string, history VerifiedHistory, operational []byte, signing ed25519.PrivateKey, guard HeadGuard, commit func() error) error {
	if !history.verified || history.Head == "" || len(history.Entries) == 0 || history.Entries[0].ID != history.Head {
		return fmt.Errorf("remote snapshot history was not verified")
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

func writeHistoryStageFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func validHistorySnapshotID(id string) bool {
	if len(id) != 64 || strings.ToLower(id) != id {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}
