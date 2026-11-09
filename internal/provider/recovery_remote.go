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
	maxRecoveryRepoBytes = maxRecoveryBytes
)

type remoteSnapshotEntry struct {
	id         string
	objectOID  string
	catalogOID string
}

const historySelectionPath = "history/selection.json"
const stagedRemoteHeadPath = ".cifrarium-staged-remote-head"
const stagedRemoteBytesPath = ".cifrarium-staged-remote-bytes"

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
	if err := g.configurePartialClone(ctx); err != nil {
		return fmt.Errorf("configure bounded remote history staging: %w", err)
	}
	if err := g.checkRecoveryRepositorySize(ctx); err != nil {
		return err
	}
	head, err := g.fetchRecoveryHead(ctx)
	if err != nil {
		return fmt.Errorf("read private GitHub provider: %w", err)
	}
	if err := g.checkLocalRecoveryObjectSize(ctx); err != nil {
		return err
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
			apiOID, size, err := g.githubBlobSizeAtCommit(ctx, head, object.path)
			if err != nil || apiOID != object.oid || size < 0 || size > object.max {
				return fmt.Errorf("remote snapshot object metadata is invalid or exceeds its size limit")
			}
			if total > maxRecoveryBytes-size {
				return fmt.Errorf("remote snapshot history exceeds recovery limits")
			}
			data, err := g.readBlobKnownSizeLimited(ctx, object.oid, size, object.max)
			if err != nil {
				return fmt.Errorf("read remote snapshot history: %w", err)
			}
			total += size
			if err := writeProviderFileLimited(g.Dir, object.path, data, object.max); err != nil {
				return fmt.Errorf("stage remote snapshot history: %w", err)
			}
		}
	}
	if markerOID != "" {
		apiOID, size, err := g.githubBlobSizeAtCommit(ctx, head, historySelectionPath)
		if err != nil || apiOID != markerOID || size < 0 || size > limits.MaxManifestBytes {
			return fmt.Errorf("read remote history selection: invalid bounded marker")
		}
		if total > maxRecoveryBytes-size {
			return fmt.Errorf("remote snapshot history exceeds recovery limits")
		}
		marker, err := g.readBlobKnownSizeLimited(ctx, markerOID, size, limits.MaxManifestBytes)
		if err != nil {
			return fmt.Errorf("read remote history selection: invalid bounded marker")
		}
		if err := writeProviderFileLimited(g.Dir, historySelectionPath, marker, limits.MaxManifestBytes); err != nil {
			return fmt.Errorf("stage remote history selection: %w", err)
		}
		total += size
	}
	if err := writeProviderFileLimited(g.Dir, stagedRemoteBytesPath, []byte(strconv.FormatInt(total, 10)), 32); err != nil {
		return fmt.Errorf("record staged remote history size: %w", err)
	}
	if err := writeProviderFileLimited(g.Dir, stagedRemoteHeadPath, []byte(head), 128); err != nil {
		return fmt.Errorf("record remote history revision: %w", err)
	}
	return nil
}

// StageHistoricalSnapshots retrieves only the requested snapshot pairs from
// commits reachable from the staged default-branch head. It may deepen this
// temporary clone, but never updates the remote provider.
func (g Git) StageHistoricalSnapshots(ctx context.Context, ids []string) (bool, error) {
	if len(ids) == 0 {
		return true, nil
	}
	expectedBytes, err := readProviderFileLimited(g.Dir, stagedRemoteHeadPath, 128)
	if err != nil {
		return false, fmt.Errorf("historical recovery requires a staged remote revision")
	}
	expectedHead := strings.TrimSpace(string(expectedBytes))
	if !validGitObjectID(expectedHead) {
		return false, fmt.Errorf("staged remote revision is invalid")
	}
	requested := make([]string, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !validSnapshotID(id) {
			return false, fmt.Errorf("invalid historical snapshot identifier")
		}
		if !seen[id] {
			seen[id] = true
			requested = append(requested, id)
		}
	}
	sort.Strings(requested)
	if staged, err := g.stageFoundHistoricalSnapshots(ctx, expectedHead, requested); err != nil || staged {
		return staged, err
	}
	if err := g.configurePartialClone(ctx); err != nil {
		return false, fmt.Errorf("configure bounded historical object retrieval: %w", err)
	}
	for _, deepen := range []int{64, 256, 1024, 4096} {
		branch, remoteHead, err := g.remoteDefaultBranch(ctx)
		if err != nil {
			return false, err
		}
		if remoteHead != expectedHead {
			return false, fmt.Errorf("private provider changed during history recovery")
		}
		if err := g.runFilteredHistoryFetch(ctx, deepen, branch); err != nil {
			return false, fmt.Errorf("fetch older private backup history: %w", err)
		}
		if err := g.checkLocalRecoveryObjectSize(ctx); err != nil {
			return false, err
		}
		fetched, err := g.outputRecoveryLimited(ctx, 128, "rev-parse", "--verify", "FETCH_HEAD^{commit}")
		if err != nil || !strings.EqualFold(strings.TrimSpace(string(fetched)), expectedHead) {
			return false, fmt.Errorf("private provider changed during history recovery")
		}
		staged, err := g.stageFoundHistoricalSnapshots(ctx, expectedHead, requested)
		if err != nil || staged {
			return staged, err
		}
	}
	return false, nil
}

func (g Git) configurePartialClone(ctx context.Context) error {
	for _, setting := range [][2]string{
		{"extensions.partialClone", "origin"},
		{"remote.origin.promisor", "true"},
		{"remote.origin.partialCloneFilter", "blob:none"},
	} {
		if err := g.run(ctx, "config", "--local", setting[0], setting[1]); err != nil {
			return err
		}
	}
	return nil
}

func (g Git) runFilteredHistoryFetch(ctx context.Context, deepen int, branch string) error {
	return g.runFilteredFetch(ctx, "--filter=blob:none", "--deepen="+strconv.Itoa(deepen), "--no-tags", "origin", branch)
}

func (g Git) runFilteredFetch(ctx context.Context, args ...string) error {
	if err := g.validateRepositoryConfig(ctx); err != nil {
		return err
	}
	cmd, cleanup, err := g.commandAtDir(ctx, "git", append([]string{"fetch", "--quiet"}, args...)...)
	if err != nil {
		return err
	}
	defer cleanup()
	stdout := &recoveryOutputBuffer{max: 1 << 20}
	stderr := &recoveryOutputBuffer{max: 1 << 20}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(err, errRecoveryOutputLimit) {
			return fmt.Errorf("filtered history fetch output exceeds its limit")
		}
		return fmt.Errorf("git filtered fetch failed: %w", err)
	}
	if filteredFetchUnsupported(stderr.String()) {
		return fmt.Errorf("provider does not support bounded history retrieval")
	}
	return nil
}

func filteredFetchUnsupported(stderr string) bool {
	lower := strings.ToLower(stderr)
	return strings.Contains(lower, "filtering not recognized") ||
		strings.Contains(lower, "filtering not supported") ||
		(strings.Contains(lower, "filter") && strings.Contains(lower, "ignored"))
}

func (g Git) checkLocalRecoveryObjectSize(ctx context.Context) error {
	output, err := g.outputRecoveryLimited(ctx, 4096, "count-objects", "-v")
	if err != nil {
		return err
	}
	var loose, packed int64
	var hasLoose, hasPacked bool
	for _, line := range strings.Split(string(output), "\n") {
		key, value, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		if key == "size" || key == "size-pack" {
			kb, parseErr := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if parseErr != nil || kb < 0 || kb > maxRecoveryBytes/1024 {
				return fmt.Errorf("staged Git history exceeds the recovery size limit")
			}
			if key == "size" {
				loose = kb
				hasLoose = true
			} else {
				packed = kb
				hasPacked = true
			}
		}
	}
	if !hasLoose || !hasPacked {
		return fmt.Errorf("staged Git history size is unavailable")
	}
	if loose+packed > maxRecoveryBytes/1024 {
		return fmt.Errorf("staged Git history exceeds the recovery size limit")
	}
	return nil
}

func (g Git) stageFoundHistoricalSnapshots(ctx context.Context, head string, ids []string) (bool, error) {
	type pair struct {
		id          string
		objectID    string
		objectSize  int64
		catalogID   string
		catalogSize int64
	}
	pairs := make([]pair, 0, len(ids))
	for _, id := range ids {
		objectPath := "objects/" + id
		catalogPath := "catalog/" + id + ".json"
		objectID, objectSize, objectFound, err := g.historicalAddedBlob(ctx, head, objectPath, limits.MaxSnapshotCipherBytes)
		if err != nil {
			return false, err
		}
		catalogID, catalogSize, catalogFound, err := g.historicalAddedBlob(ctx, head, catalogPath, limits.MaxManifestBytes)
		if err != nil {
			return false, err
		}
		if !objectFound || !catalogFound {
			return false, nil
		}
		pairs = append(pairs, pair{id: id, objectID: objectID, objectSize: objectSize, catalogID: catalogID, catalogSize: catalogSize})
	}
	if len(pairs) == 0 {
		return false, nil
	}
	idsOnStage, err := g.List(ctx)
	if err != nil {
		return false, err
	}
	if len(idsOnStage)+len(pairs) > maxRecoverySnapshots {
		return false, fmt.Errorf("remote snapshot history exceeds the supported recovery depth")
	}
	stagedBytes, err := readProviderFileLimited(g.Dir, stagedRemoteBytesPath, 32)
	if err != nil {
		return false, fmt.Errorf("staged remote history size is unavailable")
	}
	total, err := strconv.ParseInt(strings.TrimSpace(string(stagedBytes)), 10, 64)
	if err != nil || total < 0 || total > maxRecoveryBytes {
		return false, fmt.Errorf("staged remote history size is invalid")
	}
	type stagedPair struct {
		item    pair
		object  []byte
		catalog []byte
	}
	additionalBytes := int64(0)
	for _, item := range pairs {
		if item.objectSize < 0 || item.catalogSize < 0 || additionalBytes > maxRecoveryBytes-item.objectSize-item.catalogSize {
			return false, fmt.Errorf("remote snapshot history exceeds recovery limits")
		}
		additionalBytes += item.objectSize + item.catalogSize
	}
	if total > maxRecoveryBytes-additionalBytes {
		return false, fmt.Errorf("remote snapshot history exceeds recovery limits")
	}
	stagedPairs := make([]stagedPair, 0, len(pairs))
	for _, item := range pairs {
		object, err := g.readBlobKnownSizeLimited(ctx, item.objectID, item.objectSize, limits.MaxSnapshotCipherBytes)
		if err != nil {
			return false, fmt.Errorf("read historical encrypted snapshot: %w", err)
		}
		catalog, err := g.readBlobKnownSizeLimited(ctx, item.catalogID, item.catalogSize, limits.MaxManifestBytes)
		if err != nil {
			return false, fmt.Errorf("read historical encrypted catalog: %w", err)
		}
		total += item.objectSize + item.catalogSize
		stagedPairs = append(stagedPairs, stagedPair{item: item, object: object, catalog: catalog})
	}
	if err := writeProviderFileLimited(g.Dir, stagedRemoteBytesPath, []byte(strconv.FormatInt(total, 10)), 32); err != nil {
		return false, fmt.Errorf("update staged remote history size: %w", err)
	}
	for _, staged := range stagedPairs {
		if err := writeProviderFileLimited(g.Dir, "objects/"+staged.item.id, staged.object, limits.MaxSnapshotCipherBytes); err != nil {
			return false, fmt.Errorf("stage historical encrypted snapshot: %w", err)
		}
		if err := writeProviderFileLimited(g.Dir, "catalog/"+staged.item.id+".json", staged.catalog, limits.MaxManifestBytes); err != nil {
			return false, fmt.Errorf("stage historical encrypted catalog: %w", err)
		}
	}
	return true, nil
}

func (g Git) historicalAddedBlob(ctx context.Context, head, path string, maxSize int64) (string, int64, bool, error) {
	commitBytes, err := g.outputRecoveryLimited(ctx, 128, "log", "-1", "--format=%H", "--no-renames", "--diff-filter=A", head, "--", path)
	if err != nil {
		return "", 0, false, err
	}
	commit := strings.TrimSpace(string(commitBytes))
	if commit == "" {
		return "", 0, false, nil
	}
	if !validGitObjectID(commit) {
		return "", 0, false, fmt.Errorf("provider history contains an invalid commit identifier")
	}
	tree, err := g.outputRecoveryLimited(ctx, 1024, "ls-tree", "-z", commit, "--", path)
	if err != nil {
		return "", 0, false, err
	}
	entry := bytes.TrimSuffix(tree, []byte{0})
	metadata, entryPath, ok := bytes.Cut(entry, []byte{'\t'})
	if !ok || string(entryPath) != path {
		return "", 0, false, fmt.Errorf("provider history contains an invalid snapshot path")
	}
	fields := strings.Fields(string(metadata))
	if len(fields) != 3 || fields[0] != "100644" || fields[1] != "blob" || !validGitObjectID(fields[2]) {
		return "", 0, false, fmt.Errorf("provider history contains an unsafe snapshot object")
	}
	apiOID, size, err := g.githubBlobSizeAtCommit(ctx, commit, path)
	if err != nil {
		return "", 0, false, err
	}
	if apiOID != fields[2] {
		return "", 0, false, fmt.Errorf("private provider snapshot metadata changed")
	}
	if size < 0 || size > maxSize {
		return "", 0, false, fmt.Errorf("historical snapshot object exceeds its size limit")
	}
	return fields[2], size, true, nil
}

func (g Git) githubBlobSizeAtCommit(ctx context.Context, commit, path string) (string, int64, error) {
	tree, err := g.outputRecoveryLimited(ctx, 128, "rev-parse", "--verify", commit+"^{tree}")
	if err != nil {
		return "", 0, err
	}
	treeID := strings.TrimSpace(string(tree))
	if !validGitObjectID(treeID) {
		return "", 0, fmt.Errorf("provider history contains an invalid tree identifier")
	}
	slug, err := githubRepoSlug(g.Remote)
	if err != nil {
		return "", 0, err
	}
	parts := strings.Split(path, "/")
	for i, part := range parts {
		query := fmt.Sprintf(`.tree[] | select(.path == %q) | [.type, .sha, (.size // -1)] | @tsv`, part)
		cmd := exec.CommandContext(ctx, "gh", "api", "repos/"+slug+"/git/trees/"+treeID, "--jq", query)
		cmd.Env = hardenedCommandEnv("gh")
		buffer := &recoveryOutputBuffer{max: 256}
		cmd.Stdout, cmd.Stderr = buffer, io.Discard
		if err := cmd.Run(); err != nil {
			return "", 0, fmt.Errorf("read bounded snapshot metadata from private provider: %w", err)
		}
		fields := strings.Split(strings.TrimSpace(buffer.String()), "\t")
		if len(fields) != 3 || !validGitObjectID(fields[1]) {
			return "", 0, fmt.Errorf("private provider returned invalid snapshot metadata")
		}
		if i < len(parts)-1 {
			if fields[0] != "tree" {
				return "", 0, fmt.Errorf("private provider snapshot path is not a directory")
			}
			treeID = fields[1]
			continue
		}
		if fields[0] != "blob" {
			return "", 0, fmt.Errorf("private provider snapshot path is not a regular file")
		}
		size, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil || size < 0 {
			return "", 0, fmt.Errorf("private provider returned an invalid snapshot size")
		}
		return fields[1], size, nil
	}
	return "", 0, fmt.Errorf("private provider snapshot path is missing")
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
	branch, remoteHash, err := g.remoteDefaultBranch(ctx)
	if err != nil {
		return "", err
	}
	if err := g.runFilteredFetch(ctx, "--filter=blob:none", "--depth=1", "--no-tags", g.Remote, branch); err != nil {
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

func (g Git) remoteDefaultBranch(ctx context.Context) (string, string, error) {
	out, err := g.outputRecoveryLimited(ctx, 4096, "ls-remote", "--symref", g.Remote, "HEAD")
	if err != nil {
		return "", "", err
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
		return "", "", fmt.Errorf("private GitHub provider has no valid default branch")
	}
	return branch, remoteHash, nil
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

func (g Git) readBlobKnownSizeLimited(ctx context.Context, oid string, size, max int64) ([]byte, error) {
	if !validGitObjectID(oid) || size < 0 || size > max {
		return nil, fmt.Errorf("remote provider object exceeds its size limit")
	}
	data, err := g.outputRecoveryLimited(ctx, size+1, "cat-file", "blob", oid)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != size {
		return nil, fmt.Errorf("remote provider object size changed")
	}
	return data, nil
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
