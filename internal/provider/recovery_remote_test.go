package provider

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/teelabs/cifrarium/internal/limits"
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

func TestParseRecoveryTreeWithSelectionAcceptsOnlyExactRegularMarker(t *testing.T) {
	raw := []byte("100644 blob 0123456789012345678901234567890123456789\tobjects/" + idA + "\x00100644 blob 1123456789012345678901234567890123456789\tcatalog/" + idA + ".json\x00100644 blob 2123456789012345678901234567890123456789\thistory/selection.json\x00")
	entries, marker, err := parseRecoveryTreeWithSelection(raw)
	if err != nil || len(entries) != 1 || marker != "2123456789012345678901234567890123456789" {
		t.Fatalf("entries=%+v marker=%q err=%v", entries, marker, err)
	}
	unsafe := []byte("120000 blob 2123456789012345678901234567890123456789\thistory/selection.json\x00")
	if _, _, err := parseRecoveryTreeWithSelection(unsafe); err == nil {
		t.Fatal("symlink history marker accepted")
	}
	unknown := []byte("100644 blob 2123456789012345678901234567890123456789\thistory/other.json\x00")
	if _, _, err := parseRecoveryTreeWithSelection(unknown); err == nil {
		t.Fatal("unknown history metadata accepted")
	}
}

func TestDownloadStagedHistorySelectionUsesBoundedNoFollowRead(t *testing.T) {
	dir := t.TempDir()
	g := Git{Dir: dir}
	if err := os.MkdirAll(filepath.Join(dir, "history"), 0700); err != nil {
		t.Fatal(err)
	}
	marker := []byte("opaque encrypted marker")
	if err := os.WriteFile(filepath.Join(dir, "history", "selection.json"), marker, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := g.DownloadHistorySelection(t.Context())
	if err != nil || !bytes.Equal(got, marker) {
		t.Fatalf("marker=%q err=%v", got, err)
	}
	if err := os.Remove(filepath.Join(dir, "history", "selection.json")); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "history", "selection.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := g.DownloadHistorySelection(t.Context()); err == nil {
		t.Fatal("history marker symlink was read")
	}
	if err := os.Remove(filepath.Join(dir, "history", "selection.json")); err != nil {
		t.Fatal(err)
	}
	oversized := bytes.Repeat([]byte{'x'}, int(limits.MaxManifestBytes)+1)
	if err := os.WriteFile(filepath.Join(dir, "history", "selection.json"), oversized, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := g.DownloadHistorySelection(t.Context()); err == nil {
		t.Fatal("oversized staged marker was read")
	}
}
