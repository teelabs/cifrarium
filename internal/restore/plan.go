package restore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/teelabs/cifrarium/internal/adapters"
	"github.com/teelabs/cifrarium/internal/store"
)

type PlanStatus string

const (
	PlanNew       PlanStatus = "new"
	PlanIdentical PlanStatus = "identical"
	PlanMerge     PlanStatus = "merge"
	PlanConflict  PlanStatus = "conflict"
)

type FilePlan struct {
	Record      store.Record
	Status      PlanStatus
	Current     []byte
	CurrentMode os.FileMode
	NeedsChoice bool
	Reason      string
}

type ConflictChoice string

const (
	ChoiceOverwrite ConflictChoice = "overwrite"
	ChoiceKeep      ConflictChoice = "keep"
	ChoiceCancel    ConflictChoice = "cancel"
)

// BuildFilePlan reads all selected destinations in one safe preflight pass and
// marks files that can be restored, skipped, merged, or need a per-file choice.
func BuildFilePlan(home string, history VerifiedHistory, snapshotID string, selected []store.Record) ([]FilePlan, error) {
	targetIndex := -1
	for i, entry := range history.Entries {
		if entry.ID == snapshotID {
			targetIndex = i
			break
		}
	}
	if targetIndex < 0 {
		return nil, fmt.Errorf("selected snapshot is not in the verified history")
	}
	targetRecords := make(map[string]store.Record, len(history.Entries[targetIndex].Records))
	for _, record := range history.Entries[targetIndex].Records {
		targetRecords[record.Path] = record
	}
	for _, record := range selected {
		_, allowed := adapters.RestoreAdapterForPath(record.Path)
		if !allowed {
			return nil, fmt.Errorf("snapshot contains a path outside the adapter allowlist")
		}
		authenticated, ok := targetRecords[record.Path]
		if !ok || authenticated.Mode != record.Mode || !bytes.Equal(authenticated.Data, record.Data) {
			return nil, fmt.Errorf("selected file does not match the verified snapshot")
		}
	}
	states, err := store.InspectRestore(home, selected)
	if err != nil {
		return nil, err
	}
	stateByPath := make(map[string]store.RestoreDestination, len(states))
	for _, state := range states {
		stateByPath[state.Path] = state
	}
	ordered := append([]store.Record(nil), selected...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
	plan := make([]FilePlan, 0, len(ordered))
	for _, record := range ordered {
		state := stateByPath[record.Path]
		item := FilePlan{Record: record, Current: state.Data, CurrentMode: state.Mode}
		switch {
		case !state.Exists:
			item.Status = PlanNew
		case bytes.Equal(state.Data, record.Data):
			item.Status = PlanIdentical
		default:
			var verifiedVersions [][]byte
			for _, historical := range history.Entries[targetIndex+1:] {
				for _, old := range historical.Records {
					if old.Path == record.Path {
						verifiedVersions = append(verifiedVersions, old.Data)
					}
				}
			}
			merged, usedBase, conflict, err := MergeAgainstVerifiedBase(state.Data, record.Data, verifiedVersions)
			if err != nil {
				return nil, fmt.Errorf("merge %s: %w", record.Path, err)
			}
			if usedBase && !conflict {
				item.Record.Data = merged
				item.Status = PlanMerge
			} else {
				item.Status = PlanConflict
				item.NeedsChoice = true
				item.Reason = "no verified common text base"
				if usedBase && conflict {
					item.Reason = "three-way merge conflict"
				} else if bytes.IndexByte(state.Data, 0) >= 0 || bytes.IndexByte(record.Data, 0) >= 0 {
					item.Reason = "non-text file"
				}
			}
		}
		plan = append(plan, item)
	}
	return plan, nil
}

func ResolveFilePlan(plan []FilePlan, choices map[string]ConflictChoice) ([]store.Record, error) {
	records := make([]store.Record, 0, len(plan))
	for _, item := range plan {
		switch item.Status {
		case PlanIdentical:
			continue
		case PlanConflict:
			switch choices[item.Record.Path] {
			case ChoiceOverwrite:
				records = append(records, item.Record)
			case ChoiceKeep:
				continue
			case ChoiceCancel:
				return nil, fmt.Errorf("restore cancelled")
			default:
				return nil, fmt.Errorf("restore choice required for %s", item.Record.Path)
			}
		case PlanNew, PlanMerge:
			records = append(records, item.Record)
		default:
			return nil, fmt.Errorf("invalid restore plan")
		}
	}
	return records, nil
}

// Fingerprint binds an interactive terminal preflight to a fresh daemon
// preflight without sending file contents over the control socket.
func Fingerprint(plan []FilePlan) (string, error) {
	type entry struct {
		Path        string     `json:"path"`
		Status      PlanStatus `json:"status"`
		CurrentMode uint32     `json:"currentMode"`
		CurrentHash string     `json:"currentHash"`
		RestoreMode uint32     `json:"restoreMode"`
		RestoreHash string     `json:"restoreHash"`
	}
	entries := make([]entry, 0, len(plan))
	for _, item := range plan {
		currentHash := sha256.Sum256(item.Current)
		restoreHash := sha256.Sum256(item.Record.Data)
		entries = append(entries, entry{Path: item.Record.Path, Status: item.Status, CurrentMode: uint32(item.CurrentMode), CurrentHash: hex.EncodeToString(currentHash[:]), RestoreMode: item.Record.Mode, RestoreHash: hex.EncodeToString(restoreHash[:])})
	}
	encoded, err := json.Marshal(entries)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(encoded)
	return hex.EncodeToString(hash[:]), nil
}
