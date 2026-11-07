package restore

import (
	"testing"

	"github.com/teelabs/cifrarium/internal/store"
)

func TestSelectSnapshotRecordsByAdapterAndFile(t *testing.T) {
	records := []store.Record{
		{Path: ".codex/config.toml", Data: []byte("codex")},
		{Path: ".zshrc", Data: []byte("zsh")},
		{Path: ".config/starship.toml", Data: []byte("starship")},
	}
	selected, err := SelectRecords(records, map[string]bool{"codex": true}, map[string]bool{".zshrc": true})
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 2 || selected[0].Path != ".codex/config.toml" || selected[1].Path != ".zshrc" {
		t.Fatalf("selected=%+v", selected)
	}
}

func TestSelectSnapshotRecordsRejectsSignedPathsOutsideAdapterAllowlist(t *testing.T) {
	records := []store.Record{
		{Path: ".codex/config.toml", Data: []byte("codex")},
		{Path: ".ssh/authorized_keys", Data: []byte("attacker-controlled")},
	}
	if _, err := SelectRecords(records, map[string]bool{"codex": true}, nil); err == nil {
		t.Fatal("signed record outside Cifrarium adapter locations accepted")
	}
}
