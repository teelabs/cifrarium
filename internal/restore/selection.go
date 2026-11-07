package restore

import (
	"fmt"

	"github.com/teelabs/cifrarium/internal/adapters"
	"github.com/teelabs/cifrarium/internal/store"
)

var restoreAdapters = map[string]bool{"codex": true, "oh-my-zsh": true, "starship": true}

// SelectRecords applies the interactive adapter/file selection to a decrypted
// snapshot after enforcing the capture adapter allowlist for every record.
func SelectRecords(records []store.Record, selectedAdapters, selectedPaths map[string]bool) ([]store.Record, error) {
	for name, selected := range selectedAdapters {
		if selected && !restoreAdapters[name] {
			return nil, fmt.Errorf("unknown restore adapter")
		}
	}
	available := make(map[string]bool, len(records))
	selected := make([]store.Record, 0, len(records))
	for _, record := range records {
		adapter, allowed := adapters.RestoreAdapterForPath(record.Path)
		if !allowed {
			return nil, fmt.Errorf("snapshot contains a path outside the adapter allowlist")
		}
		if available[record.Path] {
			return nil, fmt.Errorf("snapshot contains duplicate file paths")
		}
		available[record.Path] = true
		if selectedAdapters[adapter] || selectedPaths[record.Path] {
			selected = append(selected, record)
		}
	}
	for path, include := range selectedPaths {
		if include && !available[path] {
			return nil, fmt.Errorf("selected file is not in this snapshot")
		}
	}
	return selected, nil
}
