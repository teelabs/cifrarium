package restore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/teelabs/cifrarium/internal/store"
)

func TestBuildFilePlanSkipsIdenticalAndMergesOnlyVerifiedHistoryMatches(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte("base\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".zprofile"), []byte("same\n"), 0600); err != nil {
		t.Fatal(err)
	}
	history := VerifiedHistory{Head: "new", Entries: []VerifiedSnapshot{
		{ID: "new", Records: []store.Record{{Path: ".zshrc", Data: []byte("incoming\n"), Mode: 0600}, {Path: ".zprofile", Data: []byte("same\n"), Mode: 0600}, {Path: ".config/starship.toml", Data: []byte("new\n"), Mode: 0600}}},
		{ID: "base", Records: []store.Record{{Path: ".zshrc", Data: []byte("base\n"), Mode: 0600}}},
	}}
	plan, err := BuildFilePlan(home, history, "new", history.Entries[0].Records)
	if err != nil {
		t.Fatal(err)
	}
	statuses := make(map[string]PlanStatus, len(plan))
	for _, item := range plan {
		statuses[item.Record.Path] = item.Status
	}
	if len(plan) != 3 || statuses[".zshrc"] != PlanMerge || statuses[".zprofile"] != PlanIdentical || statuses[".config/starship.toml"] != PlanNew {
		t.Fatalf("plan=%+v", plan)
	}
	for _, item := range plan {
		if item.Record.Path == ".zshrc" && string(item.Record.Data) != "incoming\n" {
			t.Fatalf("merged data=%q", item.Record.Data)
		}
	}
}

func TestBuildFilePlanRequiresExplicitChoiceWhenNoBaseIsProven(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte("local edit\n"), 0600); err != nil {
		t.Fatal(err)
	}
	history := VerifiedHistory{Head: "new", Entries: []VerifiedSnapshot{
		{ID: "new", Records: []store.Record{{Path: ".zshrc", Data: []byte("incoming\n"), Mode: 0600}}},
		{ID: "base", Records: []store.Record{{Path: ".zshrc", Data: []byte("old\n"), Mode: 0600}}},
	}}
	plan, err := BuildFilePlan(home, history, "new", history.Entries[0].Records)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 1 || plan[0].Status != PlanConflict || !plan[0].NeedsChoice {
		t.Fatalf("plan=%+v", plan)
	}
}

func TestBuildFilePlanWithOnlySelectedSnapshotNeverMergesAgainstUnverifiedHistory(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte("local edits\n"), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot := VerifiedSnapshot{ID: "candidate", Records: []store.Record{{Path: ".zshrc", Data: []byte("backup version\n"), Mode: 0600}}}
	plan, err := BuildFilePlan(home, VerifiedHistory{Head: snapshot.ID, Entries: []VerifiedSnapshot{snapshot}}, snapshot.ID, snapshot.Records)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 1 || plan[0].Status != PlanConflict || !plan[0].NeedsChoice || plan[0].Reason != "no verified common text base" {
		t.Fatalf("plan = %+v; missing ancestry must require explicit conflict handling", plan)
	}
}

func TestFingerprintChangesWhenPreflightDestinationChanges(t *testing.T) {
	base := []FilePlan{{Record: store.Record{Path: ".zshrc", Mode: 0600, Data: []byte("wanted")}, Status: PlanConflict, Current: []byte("before"), CurrentMode: 0600}}
	first, err := Fingerprint(base)
	if err != nil {
		t.Fatal(err)
	}
	base[0].Current = []byte("changed after prompt")
	second, err := Fingerprint(base)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("destination change did not invalidate preflight fingerprint")
	}
}
