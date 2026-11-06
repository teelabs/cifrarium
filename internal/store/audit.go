package store

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/teelabs/cifrarium/internal/limits"
)

type AuditStatus string

const (
	AuditMatches    AuditStatus = "matches"
	AuditDiffers    AuditStatus = "differs"
	AuditNoSnapshot AuditStatus = "noSnapshot"
)

// AuditResult describes differences between current allowlisted records and
// the verified active snapshot. It contains relative paths and the snapshot
// identifier, never record data or fingerprints.
type AuditResult struct {
	Status         AuditStatus `json:"status"`
	Snapshot       string      `json:"snapshot,omitempty"`
	Added          []string    `json:"added"`
	Missing        []string    `json:"missing"`
	ContentChanged []string    `json:"contentChanged"`
	ModeChanged    []string    `json:"modeChanged"`
}

type auditHeadState struct {
	rawHead  []byte
	guard    string
	manifest Manifest
	hasHead  bool
}

// AuditCurrent runs capture and comparison under a shared recovery lock when
// one already exists. If no lock exists, it verifies that neither the active
// head nor its keyring guard changes across the complete read. It never
// creates the recovery lock or changes vault/keyring state.
func (v *Vault) AuditCurrent(capture func() ([]Record, error)) (AuditResult, error) {
	var result AuditResult
	err := withVaultAuditLock(v.Root, func() error {
		before, err := v.readAuditHeadState()
		if err != nil {
			return err
		}
		if !before.hasHead {
			after, err := v.readAuditHeadState()
			if err != nil {
				return err
			}
			if !sameAuditHeadState(before, after) {
				return fmt.Errorf("vault head changed during snapshot audit")
			}
			result = emptyAuditResult(AuditNoSnapshot)
			return nil
		}
		if capture == nil {
			return fmt.Errorf("snapshot audit requires a capture function")
		}

		baseline, err := v.readAuditRecords(before)
		if err != nil {
			return err
		}
		current, err := capture()
		if err != nil {
			return err
		}
		if err := validateRecords(current); err != nil {
			return err
		}
		after, err := v.readAuditHeadState()
		if err != nil {
			return err
		}
		if !sameAuditHeadState(before, after) {
			return fmt.Errorf("vault head changed during snapshot audit")
		}

		result = compareAuditRecords(before.manifest.Snapshot, baseline, current)
		return nil
	})
	if err != nil {
		return AuditResult{}, err
	}
	return result, nil
}

func (v *Vault) readAuditHeadState() (auditHeadState, error) {
	state := auditHeadState{}
	if v.Guard != nil {
		guard, err := v.Guard.CatalogHead()
		if err != nil {
			return auditHeadState{}, err
		}
		state.guard = guard
	}
	rawHead, err := readLimitedFile(filepath.Join(v.Root, "head.json"), limits.MaxManifestBytes)
	if os.IsNotExist(err) {
		if state.guard != "" {
			return auditHeadState{}, fmt.Errorf("catalog head missing while keyring guard is set")
		}
		return state, nil
	}
	if err != nil {
		return auditHeadState{}, err
	}
	manifest, err := OpenManifest(rawHead, v.Operational)
	if err != nil {
		return auditHeadState{}, err
	}
	if manifest.Snapshot == "" || filepath.Base(manifest.Snapshot) != manifest.Snapshot {
		return auditHeadState{}, fmt.Errorf("invalid catalog head")
	}
	if state.guard != "" && state.guard != manifest.Snapshot {
		return auditHeadState{}, fmt.Errorf("catalog rollback detected")
	}
	state.rawHead = rawHead
	state.manifest = manifest
	state.hasHead = true
	return state, nil
}

func (v *Vault) readAuditRecords(state auditHeadState) ([]Record, error) {
	if len(v.Signing) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("snapshot audit signing key is unavailable")
	}
	pub := v.Signing.Public().(ed25519.PublicKey)
	if err := v.VerifyChain(state.manifest.Snapshot, pub); err != nil {
		return nil, err
	}
	rawCatalog, err := readLimitedFile(filepath.Join(v.Root, "catalog", state.manifest.Snapshot+".json"), limits.MaxManifestBytes)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(state.rawHead, rawCatalog) {
		return nil, fmt.Errorf("catalog head does not match current catalog entry")
	}
	ciphertext, err := readLimitedFile(filepath.Join(v.Root, "snapshots", state.manifest.Snapshot), limits.MaxSnapshotCipherBytes)
	if err != nil {
		return nil, err
	}
	if err := v.VerifySnapshot(state.manifest, ciphertext, pub); err != nil {
		return nil, err
	}
	records, err := v.RecordsFromCiphertext(ciphertext)
	if err != nil {
		return nil, err
	}
	return records, nil
}

func sameAuditHeadState(left, right auditHeadState) bool {
	return left.hasHead == right.hasHead && left.guard == right.guard && bytes.Equal(left.rawHead, right.rawHead)
}

func compareAuditRecords(snapshot string, baseline, current []Record) AuditResult {
	baselineByPath := make(map[string]Record, len(baseline))
	currentByPath := make(map[string]Record, len(current))
	for _, record := range baseline {
		baselineByPath[record.Path] = record
	}
	for _, record := range current {
		currentByPath[record.Path] = record
	}
	result := emptyAuditResult("")
	result.Snapshot = snapshot
	for path, record := range currentByPath {
		previous, ok := baselineByPath[path]
		if !ok {
			result.Added = append(result.Added, path)
			continue
		}
		if !bytes.Equal(previous.Data, record.Data) {
			result.ContentChanged = append(result.ContentChanged, path)
		}
		if previous.Mode != record.Mode {
			result.ModeChanged = append(result.ModeChanged, path)
		}
	}
	for path := range baselineByPath {
		if _, ok := currentByPath[path]; !ok {
			result.Missing = append(result.Missing, path)
		}
	}
	sort.Strings(result.Added)
	sort.Strings(result.Missing)
	sort.Strings(result.ContentChanged)
	sort.Strings(result.ModeChanged)
	if len(result.Added)+len(result.Missing)+len(result.ContentChanged)+len(result.ModeChanged) == 0 {
		result.Status = AuditMatches
	} else {
		result.Status = AuditDiffers
	}
	return result
}

func emptyAuditResult(status AuditStatus) AuditResult {
	return AuditResult{
		Status:         status,
		Added:          []string{},
		Missing:        []string{},
		ContentChanged: []string{},
		ModeChanged:    []string{},
	}
}
