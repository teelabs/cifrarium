package restore

import (
	"bytes"
	"testing"
)

func TestMergeAgainstVerifiedBaseUsesOnlyAnExactHistoricalMatch(t *testing.T) {
	current := []byte("version one\n")
	incoming := []byte("version two\n")
	merged, used, conflict, err := MergeAgainstVerifiedBase(current, incoming, [][]byte{[]byte("older\n"), current})
	if err != nil {
		t.Fatal(err)
	}
	if !used || conflict || !bytes.Equal(merged, incoming) {
		t.Fatalf("merged=%q used=%v conflict=%v", merged, used, conflict)
	}
}

func TestMergeAgainstVerifiedBaseRefusesUnprovenOrBinaryBases(t *testing.T) {
	for _, tc := range []struct {
		name    string
		current []byte
		history [][]byte
	}{
		{name: "no exact version", current: []byte("local edit\n"), history: [][]byte{[]byte("older\n")}},
		{name: "binary file", current: []byte{0, 1, 2}, history: [][]byte{{0, 1, 2}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			merged, used, conflict, err := MergeAgainstVerifiedBase(tc.current, []byte("incoming\n"), tc.history)
			if err != nil {
				t.Fatal(err)
			}
			if used || conflict || merged != nil {
				t.Fatalf("merged=%q used=%v conflict=%v; want no merge", merged, used, conflict)
			}
		})
	}
}
