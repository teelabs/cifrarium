package store

import (
	"fmt"
	"os"
)

type RestoreDestination struct {
	Path   string
	Exists bool
	Data   []byte
	Mode   os.FileMode
}

// InspectRestore validates every selected destination and reads regular
// existing files without creating parents or changing target state.
func InspectRestore(target string, records []Record) ([]RestoreDestination, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("restore selection is empty")
	}
	seen := make(map[string]bool, len(records))
	for _, record := range records {
		if err := validateRestoreRecordPath(record.Path); err != nil {
			return nil, err
		}
		if seen[record.Path] {
			return nil, fmt.Errorf("duplicate restore path %q", record.Path)
		}
		seen[record.Path] = true
	}
	return inspectRestoreDestinations(target, records)
}
