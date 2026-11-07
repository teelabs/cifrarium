package provider

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	tree, err := g.outputRecoveryLimited(ctx, 1<<20, "ls-tree", "-r", "-z", head, "--", "objects", "catalog")
	if err != nil {
		return fmt.Errorf("list remote snapshot history: %w", err)
	}
	entries, err := parseRecoveryTree(tree)
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
	return nil
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
	byID := make(map[string]*remoteSnapshotEntry)
	seenPaths := make(map[string]struct{})
	for _, record := range strings.Split(string(raw), "\x00") {
		if record == "" {
			continue
		}
		metadata, path, ok := strings.Cut(record, "\t")
		fields := strings.Fields(metadata)
		if !ok || len(fields) != 3 || fields[0] != "100644" || fields[1] != "blob" || !validGitObjectID(fields[2]) {
			return nil, fmt.Errorf("remote provider contains an unsafe snapshot entry")
		}
		if _, duplicate := seenPaths[path]; duplicate {
			return nil, fmt.Errorf("remote provider contains a duplicate snapshot entry")
		}
		seenPaths[path] = struct{}{}
		var id string
		var object, catalog bool
		switch {
		case strings.HasPrefix(path, "objects/"):
			id, object = strings.TrimPrefix(path, "objects/"), true
		case strings.HasPrefix(path, "catalog/") && strings.HasSuffix(path, ".json"):
			id, catalog = strings.TrimSuffix(strings.TrimPrefix(path, "catalog/"), ".json"), true
		default:
			return nil, fmt.Errorf("remote provider contains a path outside snapshot storage")
		}
		if !validSnapshotID(id) {
			return nil, fmt.Errorf("remote provider contains an invalid snapshot identifier")
		}
		entry := byID[id]
		if entry == nil {
			if len(byID) >= maxRecoverySnapshots {
				return nil, fmt.Errorf("remote snapshot history exceeds the supported depth")
			}
			entry = &remoteSnapshotEntry{id: id}
			byID[id] = entry
		}
		if object {
			if entry.objectOID != "" {
				return nil, fmt.Errorf("remote provider contains duplicate snapshots")
			}
			entry.objectOID = fields[2]
		} else if catalog {
			if entry.catalogOID != "" {
				return nil, fmt.Errorf("remote provider contains duplicate catalog entries")
			}
			entry.catalogOID = fields[2]
		}
	}
	entries := make([]remoteSnapshotEntry, 0, len(byID))
	for _, entry := range byID {
		if entry.objectOID == "" || entry.catalogOID == "" {
			return nil, fmt.Errorf("remote provider snapshot or catalog is missing")
		}
		entries = append(entries, *entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].id < entries[j].id })
	return entries, nil
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
