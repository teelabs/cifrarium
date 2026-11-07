package provider

import (
	"strings"
	"testing"
)

var idA = strings.Repeat("a", 64)

func TestParseRecoveryTreeAcceptsOnlyRegularSnapshotObjectsAndCatalogs(t *testing.T) {
	raw := []byte("100644 blob 0123456789012345678901234567890123456789\tobjects/" + idA + "\x00100644 blob 1123456789012345678901234567890123456789\tcatalog/" + idA + ".json\x00")
	entries, err := parseRecoveryTree(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].id != idA || entries[0].objectOID == "" || entries[0].catalogOID == "" {
		t.Fatalf("entries=%+v", entries)
	}
}

func TestParseRecoveryTreeRejectsUnexpectedModesPathsAndIncompletePairs(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "symlink", raw: []byte("120000 blob 0123456789012345678901234567890123456789\tobjects/" + idA + "\x00")},
		{name: "unowned path", raw: []byte("100644 blob 0123456789012345678901234567890123456789\t.ssh/authorized_keys\x00")},
		{name: "object without catalog", raw: []byte("100644 blob 0123456789012345678901234567890123456789\tobjects/" + idA + "\x00")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseRecoveryTree(tc.raw); err == nil {
				t.Fatal("untrusted provider tree accepted")
			}
		})
	}
}

func TestRecoveryOutputBufferEnforcesBound(t *testing.T) {
	buffer := &recoveryOutputBuffer{max: 3}
	if _, err := buffer.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if _, err := buffer.Write([]byte("d")); err != errRecoveryOutputLimit {
		t.Fatalf("overflow error=%v", err)
	}
	if buffer.String() != "abc" {
		t.Fatalf("buffer=%q", buffer.String())
	}
}
