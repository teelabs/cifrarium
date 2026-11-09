package provider

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/teelabs/cifrarium/internal/limits"
)

const (
	maxRecoverySnapshots = 1024
	maxRecoveryBytes     = 512 << 20
	maxRecoveryRepoBytes = 1 << 30
)

type remoteSnapshotEntry struct {
	id         string
	objectOID  string
	catalogOID string
}

const historySelectionPath = "history/selection.json"
const stagedRemoteHeadPath = ".cifrarium-staged-remote-head"

// StageRemoteSnapshots fetches the configured GitHub branch into this local
// staging checkout and copies only bounded regular snapshot/catalog blobs into
// the provider layout. It never checks out repository files or writes remotely.
func (g Git) StageRemoteSnapshots(ctx context.Context) error {
	if err := g.Ensure(ctx); err != nil {
		return err
	}
	if err := g.VerifyPrivate(ctx); err != nil {
		return fmt.Errorf("private GitHub provider verification failed: %w", err)
	}
	if err := g.checkRecoveryRepositorySize(ctx); err != nil {
		return err
	}
	head, err := g.fetchRecoveryHead(ctx)
	if err != nil {
		return fmt.Errorf("read private GitHub provider: %w", err)
	}
	if head == "" {
		return fmt.Errorf("private GitHub provider has no snapshot history")
	}
	tree, err := g.outputRecoveryLimited(ctx, 1<<20, "ls-tree", "-r", "-z", head, "--", "objects", "catalog", "history")
	if err != nil {
		return fmt.Errorf("list remote snapshot history: %w", err)
	}
	entries, markerOID, err := parseRecoveryTreeWithSelection(tree)
	if err != nil {
		return err
	}
	var total int64
	for _, entry := range entries {
		for _, object := range []struct {
			path string
			oid  string
			max  int64
		}{{filepath.ToSlash(filepath.Join("objects", entry.id)), entry.objectOID, limits.MaxSnapshotCipherBytes}, {filepath.ToSlash(filepath.Join("catalog", entry.id+".json")), entry.catalogOID, limits.MaxManifestBytes}} {
			data, size, err := g.readBlobLimited(ctx, object.oid, object.max)
			if err != nil {
				return fmt.Errorf("read remote snapshot history: %w", err)
			}
			if int64(len(data)) != size || total > maxRecoveryBytes-size {
				return fmt.Errorf("remote snapshot history exceeds recovery limits")
			}
			total += size
			if err := writeProviderFileLimited(g.Dir, object.path, data, object.max); err != nil {
				return fmt.Errorf("stage remote snapshot history: %w", err)
			}
		}
	}
	if markerOID != "" {
		marker, size, err := g.readBlobLimited(ctx, markerOID, limits.MaxManifestBytes)
		if err != nil || int64(len(marker)) != size {
			return fmt.Errorf("read remote history selection: invalid bounded marker")
		}
		if total > maxRecoveryBytes-size {
			return fmt.Errorf("remote snapshot history exceeds recovery limits")
		}
		if err := writeProviderFileLimited(g.Dir, historySelectionPath, marker, limits.MaxManifestBytes); err != nil {
			return fmt.Errorf("stage remote history selection: %w", err)
		}
	}
	if err := writeProviderFileLimited(g.Dir, stagedRemoteHeadPath, []byte(head), 128); err != nil {
		return fmt.Errorf("record remote history revision: %w", err)
	}
	return nil
}

// DownloadHistorySelection returns the staged encrypted selection marker, if
// present. The marker is opaque here and is authenticated by the store layer.
func (g Git) DownloadHistorySelection(context.Context) ([]byte, error) {
	data, err := readProviderFileLimited(g.Dir, filepath.FromSlash(historySelectionPath), limits.MaxManifestBytes)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := limits.CheckBytes(len(data), limits.MaxManifestBytes); err != nil {
		return nil, err
	}
	return data, nil
}

// ReadRemoteHistorySelection reads the current encrypted marker together with
// the commit that protects it from a concurrent provider update.
func (g Git) ReadRemoteHistorySelection(ctx context.Context) ([]byte, string, error) {
	_, revision, err := g.remoteHead(ctx)
	if err != nil {
		return nil, "", err
	}
	if revision == "" {
		return nil, "", nil
	}
	mode, kind, oid, exists, err := g.remoteTreeEntry(ctx, revision, historySelectionPath)
	if err != nil {
		return nil, "", err
	}
	if !exists {
		return nil, revision, nil
	}
	if mode != "100644" || kind != "blob" || !validGitObjectID(oid) {
		return nil, "", fmt.Errorf("remote history marker is not a regular file")
	}
	marker, _, err := g.readBlobLimited(ctx, oid, limits.MaxManifestBytes)
	if err != nil {
		return nil, "", err
	}
	return marker, revision, nil
}

// UploadHistorySelection writes only the encrypted marker and pushes a
// fast-forward commit based on the exact revision staged by this instance.
func (g Git) UploadHistorySelection(ctx context.Context, marker []byte) error {
	if err := limits.CheckBytes(len(marker), limits.MaxManifestBytes); err != nil {
		return err
	}
	parentBytes, err := readProviderFileLimited(g.Dir, stagedRemoteHeadPath, 128)
	if err != nil || !validGitObjectID(strings.TrimSpace(string(parentBytes))) {
		return fmt.Errorf("history selection requires a staged remote revision")
	}
	parent := strings.TrimSpace(string(parentBytes))
	_, currentParent, err := g.remoteHead(ctx)
	if err != nil {
		return err
	}
	if parent != currentParent {
		return fmt.Errorf("remote provider changed after history inspection; inspect again")
	}
	if err := g.VerifyPrivate(ctx); err != nil {
		return fmt.Errorf("privacy verification before history selection failed: %w", err)
	}
	return g.uploadRemoteObjectsExpected(ctx, "select canonical backup history", parent, gitObject{historySelectionPath, marker})
}

// UploadSnapshotWithHistorySelection atomically publishes the encrypted
// snapshot, signed catalog, and advanced encrypted marker on one commit.
func (g Git) UploadSnapshotWithHistorySelection(ctx context.Context, id string, ciphertext, manifest, marker []byte, expectedRevision string) error {
	if err := g.Ensure(ctx); err != nil {
		return err
	}
	if err := validateID(id); err != nil {
		return err
	}
	if err := limits.CheckBytes(len(ciphertext), limits.MaxSnapshotCipherBytes); err != nil {
		return err
	}
	if err := limits.CheckBytes(len(manifest), limits.MaxManifestBytes); err != nil {
		return err
	}
	if err := limits.CheckBytes(len(marker), limits.MaxManifestBytes); err != nil {
		return err
	}
	if !validGitObjectID(expectedRevision) {
		return fmt.Errorf("canonical snapshot upload requires a verified remote revision")
	}
	if err := g.VerifyPrivate(ctx); err != nil {
		return fmt.Errorf("privacy verification before canonical snapshot upload failed: %w", err)
	}
	objects := []gitObject{
		{filepath.ToSlash(filepath.Join("objects", id)), ciphertext},
		{filepath.ToSlash(filepath.Join("catalog", id+".json")), manifest},
		{historySelectionPath, marker},
	}
	if err := g.uploadRemoteObjectsExpected(ctx, "snapshot "+id, expectedRevision, objects...); err != nil {
		return err
	}
	for _, object := range objects {
		max := int64(limits.MaxSnapshotCipherBytes)
		if strings.HasPrefix(object.path, "catalog/") || object.path == historySelectionPath {
			max = limits.MaxManifestBytes
		}
		if err := writeProviderFileLimited(g.Dir, object.path, object.data, max); err != nil {
			return fmt.Errorf("provider accepted canonical snapshot but local checkout update failed; retry upload to repair it: %w", err)
		}
	}
	return nil
}

func (g Git) uploadRemoteObjectsExpected(ctx context.Context, message, expectedParent string, objects ...gitObject) error {
	_, currentParent, err := g.remoteHead(ctx)
	if err != nil {
		return err
	}
	if currentParent != expectedParent {
		return fmt.Errorf("remote provider changed during history operation; inspect again")
	}
	indexPath, cleanup, err := g.newUploadIndex(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	hashes := make([]string, len(objects))
	for i, object := range objects {
		cmd, closeCommand, err := g.commandAtDir(ctx, "git", "hash-object", "-w", "--stdin")
		if err != nil {
			return err
		}
		cmd.Stdin = bytes.NewReader(object.data)
		hash, runErr := cmd.Output()
		closeCommand()
		if runErr != nil {
			return runErr
		}
		hashes[i] = strings.TrimSpace(string(hash))
		if !validGitObjectID(hashes[i]) {
			return fmt.Errorf("invalid provider object hash")
		}
	}
	return g.commitAndPushRemoteAt(ctx, indexPath, message, objects, hashes, expectedParent)
}

func (g Git) checkRecoveryRepositorySize(ctx context.Context) error {
	slug, err := githubRepoSlug(g.Remote)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "gh", "api", "repos/"+slug, "--jq", ".size")
	cmd.Env = hardenedCommandEnv("gh")
	buffer := &recoveryOutputBuffer{max: 64}
	cmd.Stdout = buffer
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("read private provider size metadata: %w", err)
	}
	kilobytes, err := strconv.ParseInt(strings.TrimSpace(buffer.String()), 10, 64)
	if err != nil || kilobytes < 0 || kilobytes > maxRecoveryRepoBytes/1024 {
		return fmt.Errorf("private provider exceeds the recovery repository size limit")
	}
	return nil
}

func (g Git) fetchRecoveryHead(ctx context.Context) (string, error) {
	out, err := g.outputRecoveryLimited(ctx, 4096, "ls-remote", "--symref", g.Remote, "HEAD")
	if err != nil {
		return "", err
	}
	branch, remoteHash := "", ""
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 2 {
			continue
		}
		if strings.HasPrefix(fields[0], "ref: refs/heads/") && fields[1] == "HEAD" {
			branch = strings.TrimPrefix(fields[0], "ref: ")
		}
		if fields[1] == "HEAD" && validGitObjectID(fields[0]) {
			remoteHash = fields[0]
		}
	}
	if branch == "" || remoteHash == "" {
		return "", fmt.Errorf("private GitHub provider has no valid default branch")
	}
	if err := g.run(ctx, "fetch", "--depth=1", "--no-tags", g.Remote, branch); err != nil {
		return "", fmt.Errorf("fetch private provider head: %w", err)
	}
	head, err := g.outputRecoveryLimited(ctx, 128, "rev-parse", "--verify", "FETCH_HEAD^{commit}")
	if err != nil {
		return "", err
	}
	headID := strings.TrimSpace(string(head))
	if !validGitObjectID(headID) || !strings.EqualFold(headID, remoteHash) {
		return "", fmt.Errorf("private provider head changed during recovery fetch")
	}
	return headID, nil
}

func (g Git) readBlobLimited(ctx context.Context, oid string, max int64) ([]byte, int64, error) {
	sizeOutput, err := g.output(ctx, "cat-file", "-s", oid)
	if err != nil {
		return nil, 0, err
	}
	size, err := strconv.ParseInt(strings.TrimSpace(string(sizeOutput)), 10, 64)
	if err != nil || size < 0 || size > max {
		return nil, 0, fmt.Errorf("remote provider object exceeds its size limit")
	}
	data, err := g.outputRecoveryLimited(ctx, max, "cat-file", "blob", oid)
	if err != nil {
		return nil, 0, err
	}
	if int64(len(data)) != size {
		return nil, 0, fmt.Errorf("remote provider object size changed")
	}
	return data, size, nil
}

func (g Git) outputRecoveryLimited(ctx context.Context, max int64, args ...string) ([]byte, error) {
	cmd, cleanup, err := g.commandAtDir(ctx, "git", args...)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	buffer := &recoveryOutputBuffer{max: max}
	cmd.Stdout = buffer
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		if errors.Is(err, errRecoveryOutputLimit) {
			return nil, fmt.Errorf("remote recovery metadata exceeds its output limit")
		}
		return nil, err
	}
	return buffer.Bytes(), nil
}

var errRecoveryOutputLimit = errors.New("recovery command output exceeds limit")

type recoveryOutputBuffer struct {
	bytes.Buffer
	max int64
}

func (b *recoveryOutputBuffer) Write(p []byte) (int, error) {
	if int64(b.Len())+int64(len(p)) > b.max {
		return 0, errRecoveryOutputLimit
	}
	return b.Buffer.Write(p)
}

func parseRecoveryTree(raw []byte) ([]remoteSnapshotEntry, error) {
	entries, marker, err := parseRecoveryTreeWithSelection(raw)
	if err != nil {
		return nil, err
	}
	if marker != "" {
		return nil, fmt.Errorf("remote provider contains an unexpected history selection")
	}
	return entries, nil
}

func parseRecoveryTreeWithSelection(raw []byte) ([]remoteSnapshotEntry, string, error) {
	byID := make(map[string]*remoteSnapshotEntry)
	seenPaths := make(map[string]struct{})
	markerOID := ""
	for _, record := range strings.Split(string(raw), "\x00") {
		if record == "" {
			continue
		}
		metadata, path, ok := strings.Cut(record, "\t")
		fields := strings.Fields(metadata)
		if !ok || len(fields) != 3 || fields[0] != "100644" || fields[1] != "blob" || !validGitObjectID(fields[2]) {
			return nil, "", fmt.Errorf("remote provider contains an unsafe snapshot entry")
		}
		if _, duplicate := seenPaths[path]; duplicate {
			return nil, "", fmt.Errorf("remote provider contains a duplicate snapshot entry")
		}
		seenPaths[path] = struct{}{}
		var id string
		var object, catalog bool
		switch {
		case path == historySelectionPath:
			markerOID = fields[2]
			continue
		case strings.HasPrefix(path, "objects/"):
			id, object = strings.TrimPrefix(path, "objects/"), true
		case strings.HasPrefix(path, "catalog/") && strings.HasSuffix(path, ".json"):
			id, catalog = strings.TrimSuffix(strings.TrimPrefix(path, "catalog/"), ".json"), true
		default:
			return nil, "", fmt.Errorf("remote provider contains a path outside snapshot storage")
		}
		if !validSnapshotID(id) {
			return nil, "", fmt.Errorf("remote provider contains an invalid snapshot identifier")
		}
		entry := byID[id]
		if entry == nil {
			if len(byID) >= maxRecoverySnapshots {
				return nil, "", fmt.Errorf("remote snapshot history exceeds the supported depth")
			}
			entry = &remoteSnapshotEntry{id: id}
			byID[id] = entry
		}
		if object {
			if entry.objectOID != "" {
				return nil, "", fmt.Errorf("remote provider contains duplicate snapshots")
			}
			entry.objectOID = fields[2]
		} else if catalog {
			if entry.catalogOID != "" {
				return nil, "", fmt.Errorf("remote provider contains duplicate catalog entries")
			}
			entry.catalogOID = fields[2]
		}
	}
	entries := make([]remoteSnapshotEntry, 0, len(byID))
	for _, entry := range byID {
		if entry.objectOID == "" || entry.catalogOID == "" {
			return nil, "", fmt.Errorf("remote provider snapshot or catalog is missing")
		}
		entries = append(entries, *entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].id < entries[j].id })
	return entries, markerOID, nil
}

func validSnapshotID(id string) bool {
	if len(id) != 64 || strings.ToLower(id) != id {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func validGitObjectID(id string) bool {
	if len(id) != 40 && len(id) != 64 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}
