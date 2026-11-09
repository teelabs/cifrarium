package provider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/teelabs/cifrarium/internal/limits"
)

type Git struct {
	Dir    string
	Remote string
}

type gitObject struct {
	path string
	data []byte
}

type RemoteAccessError struct{ Err error }

func (e *RemoteAccessError) Error() string {
	return fmt.Sprintf("GitHub remote access failed; verify repository visibility and token permissions (tokens are never stored by Cifrarium): %v", e.Err)
}
func (e *RemoteAccessError) Unwrap() error { return e.Err }

func (g Git) run(ctx context.Context, args ...string) error {
	return g.runWithIndex(ctx, "", args...)
}

func (g Git) runWithIndex(ctx context.Context, indexPath string, args ...string) error {
	if err := g.validateRepositoryConfig(ctx); err != nil {
		return err
	}
	c, cleanup, err := g.commandAtDir(ctx, "git", args...)
	if err != nil {
		return err
	}
	defer cleanup()
	if indexPath != "" {
		c.Env = append(c.Env, "GIT_INDEX_FILE="+indexPath)
	}
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("git %v: %w (%s)", args, err, out)
	}
	return nil
}

func (g Git) output(ctx context.Context, args ...string) ([]byte, error) {
	if err := g.validateRepositoryConfig(ctx); err != nil {
		return nil, err
	}
	c, cleanup, err := g.commandAtDir(ctx, "git", args...)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	return c.Output()
}

func (g Git) command(ctx context.Context, executable string, args ...string) *exec.Cmd {
	if executable == "git" {
		args = hardenedGitArgs(args)
	}
	c := exec.CommandContext(ctx, executable, args...)
	c.Env = hardenedCommandEnv(executable)
	return c
}

func (g Git) commandAtDir(ctx context.Context, executable string, args ...string) (*exec.Cmd, func(), error) {
	if executable == "git" {
		args = hardenedGitArgs(args)
	}
	f, err := openGitDir(g.Dir)
	if err != nil {
		return nil, func() {}, err
	}
	c := anchoredGitCommand(ctx, executable, args, hardenedCommandEnv(executable), g.Dir, f)
	return c, func() { _ = f.Close() }, nil
}

func hardenedGitArgs(args []string) []string {
	return append([]string{
		"-c", "core.hooksPath=/dev/null",
		"-c", "core.fsmonitor=false",
		"-c", "core.attributesFile=/dev/null",
		"-c", "core.sshCommand=",
		"-c", "credential.helper=!/usr/bin/gh auth git-credential",
		"-c", "commit.gpgSign=false",
	}, args...)
}

func hardenedCommandEnv(executable string) []string {
	env := make([]string, 0, len(os.Environ())+4)
	for _, value := range os.Environ() {
		name, _, _ := strings.Cut(value, "=")
		if strings.HasPrefix(name, "GIT_") || strings.HasPrefix(name, "SSH_") ||
			strings.HasPrefix(name, "GH_") || name == "GITHUB_TOKEN" ||
			strings.HasPrefix(name, "CIFRARIUM_RECOVERY_SHARE_") {
			continue
		}
		env = append(env, value)
	}
	env = append(env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0")
	if executable == "gh" {
		env = append(env, "GH_PROMPT_DISABLED=1")
	}
	return env
}
func (g Git) Upload(ctx context.Context, id string, ciphertext []byte) error {
	if err := g.Ensure(ctx); err != nil {
		return err
	}
	if err := validateID(id); err != nil {
		return err
	}
	if err := g.writeObject(ctx, filepath.Join("objects", id), ciphertext); err != nil {
		return err
	}
	return g.commitAndPush(ctx, "snapshot "+id, gitObject{filepath.Join("objects", id), ciphertext})
}
func (g Git) UploadCatalog(ctx context.Context, id string, manifest []byte) error {
	if err := g.Ensure(ctx); err != nil {
		return err
	}
	if err := validateID(id); err != nil {
		return err
	}
	path := filepath.Join("catalog", id+".json")
	if err := g.writeObject(ctx, path, manifest); err != nil {
		return err
	}
	return g.commitAndPush(ctx, "catalog "+id, gitObject{path, manifest})
}
func (g Git) UploadSnapshot(ctx context.Context, id string, ciphertext, manifest []byte) error {
	return g.uploadSnapshot(ctx, id, ciphertext, manifest, nil)
}

func (g Git) UploadSnapshotWithEquivalentManifest(ctx context.Context, id string, ciphertext, manifest []byte, equivalent func([]byte) bool) error {
	return g.uploadSnapshot(ctx, id, ciphertext, manifest, equivalent)
}

func (g Git) uploadSnapshot(ctx context.Context, id string, ciphertext, manifest []byte, equivalent func([]byte) bool) error {
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
	var storedEquivalentManifest []byte
	var equivalentManifest bool
	var remoteObjectExists, remoteObjectMatches bool
	var err error
	if equivalent != nil && g.Remote != "" {
		storedEquivalentManifest, equivalentManifest, remoteObjectExists, remoteObjectMatches, err = g.remoteSnapshotEquivalent(ctx, id, ciphertext, equivalent)
		if err != nil {
			return err
		}
		if equivalentManifest && remoteObjectExists && remoteObjectMatches {
			return nil
		}
		if equivalentManifest && !remoteObjectExists {
			manifest = storedEquivalentManifest
		}
	}
	objectPath := filepath.Join("objects", id)
	catalogPath := filepath.Join("catalog", id+".json")
	if err := g.writeObject(ctx, objectPath, ciphertext); err != nil {
		return err
	}
	if err := g.writeObject(ctx, catalogPath, manifest); err != nil {
		return err
	}
	return g.commitAndPush(ctx, "snapshot "+id,
		gitObject{objectPath, ciphertext}, gitObject{catalogPath, manifest})
}

func (g Git) remoteSnapshotEquivalent(ctx context.Context, id string, ciphertext []byte, equivalent func([]byte) bool) ([]byte, bool, bool, bool, error) {
	_, parent, err := g.remoteHead(ctx)
	if err != nil || parent == "" {
		return nil, false, false, false, err
	}
	objectPath := filepath.ToSlash(filepath.Join("objects", id))
	objectMode, objectKind, remoteObjectHash, remoteObjectExists, err := g.remoteTreeEntry(ctx, parent, objectPath)
	if err != nil {
		return nil, false, false, false, err
	}
	remoteObjectMatches := false
	if remoteObjectExists && objectMode == "100644" && objectKind == "blob" {
		candidateObjectHash, err := g.hashObject(ctx, ciphertext)
		if err != nil {
			return nil, false, false, false, err
		}
		remoteObjectMatches = remoteObjectHash == candidateObjectHash
	}
	catalogPath := filepath.ToSlash(filepath.Join("catalog", id+".json"))
	catalogMode, catalogKind, blobHash, catalogExists, err := g.remoteTreeEntry(ctx, parent, catalogPath)
	if err != nil {
		return nil, false, remoteObjectExists, remoteObjectMatches, err
	}
	if !catalogExists || catalogMode != "100644" || catalogKind != "blob" {
		return nil, false, remoteObjectExists, remoteObjectMatches, nil
	}
	kind, err := g.output(ctx, "cat-file", "-t", blobHash)
	if err != nil || strings.TrimSpace(string(kind)) != "blob" {
		return nil, false, remoteObjectExists, remoteObjectMatches, nil
	}
	sizeBytes, err := g.output(ctx, "cat-file", "-s", blobHash)
	if err != nil {
		return nil, false, remoteObjectExists, remoteObjectMatches, nil
	}
	size, err := strconv.ParseInt(strings.TrimSpace(string(sizeBytes)), 10, 64)
	if err != nil {
		return nil, false, remoteObjectExists, remoteObjectMatches, fmt.Errorf("invalid provider catalog object size")
	}
	if size < 0 || size > limits.MaxManifestBytes {
		return nil, false, remoteObjectExists, remoteObjectMatches, nil
	}
	remoteManifest, err := g.output(ctx, "cat-file", "blob", blobHash)
	if err != nil || int64(len(remoteManifest)) != size {
		return nil, false, remoteObjectExists, remoteObjectMatches, nil
	}
	return remoteManifest, equivalent(remoteManifest), remoteObjectExists, remoteObjectMatches, nil
}

func (g Git) remoteTreeEntry(ctx context.Context, commit, path string) (mode, kind, hash string, exists bool, err error) {
	raw, err := g.output(ctx, "ls-tree", "-z", commit, "--", path)
	if err != nil {
		return "", "", "", false, err
	}
	if len(raw) == 0 {
		return "", "", "", false, nil
	}
	entry := bytes.TrimSuffix(raw, []byte{0})
	metadata, entryPath, ok := bytes.Cut(entry, []byte{'\t'})
	if !ok || string(entryPath) != path {
		return "", "", "", false, fmt.Errorf("invalid remote provider tree entry")
	}
	fields := strings.Fields(string(metadata))
	if len(fields) != 3 {
		return "", "", "", false, fmt.Errorf("invalid remote provider tree metadata")
	}
	return fields[0], fields[1], fields[2], true, nil
}

func (g Git) hashObject(ctx context.Context, data []byte) (string, error) {
	cmd, cleanup, err := g.commandAtDir(ctx, "git", "hash-object", "--stdin")
	if err != nil {
		return "", err
	}
	defer cleanup()
	cmd.Stdin = bytes.NewReader(data)
	hash, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("hash provider snapshot: %w", err)
	}
	text := strings.TrimSpace(string(hash))
	if len(text) != 40 {
		return "", fmt.Errorf("invalid Git object hash")
	}
	return text, nil
}
func (g Git) Download(ctx context.Context, id string) ([]byte, error) {
	if err := validateID(id); err != nil {
		return nil, err
	}
	return readProviderFileLimited(g.Dir, filepath.Join("objects", id), limits.MaxSnapshotCipherBytes)
}
func (g Git) DownloadCatalog(ctx context.Context, id string) ([]byte, error) {
	if err := validateID(id); err != nil {
		return nil, err
	}
	return readProviderFileLimited(g.Dir, filepath.Join("catalog", id+".json"), limits.MaxManifestBytes)
}
func (g Git) List(ctx context.Context) ([]string, error) {
	return listProviderFiles(g.Dir, "objects")
}
func (g Git) Health(ctx context.Context) error {
	if err := g.run(ctx, "status", "--porcelain"); err != nil {
		return err
	}
	if g.Remote != "" {
		return g.CheckRemoteAccess(ctx)
	}
	return nil
}

// CheckRemoteAccess performs a read-only remote probe. Git remains the
// credential boundary, so revoked tokens and insufficient repository access
// are diagnosed without receiving or persisting credentials in Cifrarium.
func (g Git) CheckRemoteAccess(ctx context.Context) error {
	if g.Dir == "" {
		return fmt.Errorf("provider directory is required")
	}
	if _, err := g.remoteURL(ctx); err != nil {
		return &RemoteAccessError{Err: err}
	}
	remote := "origin"
	if g.Remote != "" {
		remote = g.Remote
	}
	if err := g.run(ctx, "ls-remote", remote, "HEAD"); err != nil {
		return &RemoteAccessError{Err: err}
	}
	return nil
}

// VerifyPrivate optionally checks the GitHub repository privacy flag through
// the operator's gh authentication. The token is owned by gh and is never
// passed as an argument or persisted by Cifrarium.
func (g Git) VerifyPrivate(ctx context.Context) error {
	if g.Remote == "" {
		return fmt.Errorf("GitHub privacy cannot be verified for a local-only provider")
	}
	remote := g.Remote
	if remote == "" {
		var err error
		remote, err = g.remoteURL(ctx)
		if err != nil {
			return &RemoteAccessError{Err: err}
		}
	}
	slug, err := githubRepoSlug(remote)
	if err != nil {
		return err
	}
	cmd, cleanup, err := g.commandAtDir(ctx, "gh", "api", "repos/"+slug, "--jq", ".private")
	if err != nil {
		return err
	}
	defer cleanup()
	out, err := cmd.Output()
	if err != nil {
		return &RemoteAccessError{Err: fmt.Errorf("GitHub privacy check unavailable: %w", err)}
	}
	if strings.TrimSpace(string(out)) != "true" {
		return fmt.Errorf("GitHub repository %s is not private", slug)
	}
	return nil
}

func (g Git) validateRepositoryConfig(ctx context.Context) error {
	if g.Dir == "" {
		return nil
	}
	if _, err := os.Stat(filepath.Join(g.Dir, ".git")); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	cmd, cleanup, err := g.commandAtDir(ctx, "git", "config", "--local", "--name-only", "--get-regexp", `^(filter\.|credential\.helper$|core\.(sshCommand|attributesFile|hooksPath|fsmonitor)|include\.|url\..*\.(insteadOf|pushInsteadOf)|remote\..*\.(uploadpack|receivepack)|http\.)`)
	if err != nil {
		return err
	}
	defer cleanup()
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil
		}
		return fmt.Errorf("cannot inspect local Git configuration: %w", err)
	}
	if strings.TrimSpace(string(out)) != "" {
		return fmt.Errorf("unsafe local Git configuration rejected")
	}
	return nil
}

func (g Git) writeObject(ctx context.Context, relative string, data []byte) error {
	max := limits.MaxSnapshotCipherBytes
	if strings.HasPrefix(relative, "catalog"+string(filepath.Separator)) {
		max = limits.MaxManifestBytes
	}
	return writeProviderFileLimited(g.Dir, relative, data, max)
}

func (g Git) commitAndPush(ctx context.Context, message string, objects ...gitObject) error {
	indexPath, cleanupIndex, err := g.newUploadIndex(ctx)
	if err != nil {
		return err
	}
	defer cleanupIndex()

	hashes := make([]string, len(objects))
	for i, object := range objects {
		cmd, cleanup, err := g.commandAtDir(ctx, "git", "hash-object", "-w", "--stdin")
		if err != nil {
			return err
		}
		cmd.Stdin = bytes.NewReader(object.data)
		hash, err := cmd.Output()
		cleanup()
		if err != nil {
			return fmt.Errorf("hash provider object %s: %w", object.path, err)
		}
		hashText := strings.TrimSpace(string(hash))
		if len(hashText) != 40 {
			return fmt.Errorf("invalid Git object hash for %s", object.path)
		}
		hashes[i] = hashText
		if err := g.runWithIndex(ctx, indexPath, "update-index", "--add", "--cacheinfo", "100644,"+hashText+","+object.path); err != nil {
			return err
		}
	}
	// Provider checkouts may predate Cifrarium or may already exist without
	// local commit identity. Set a stable service identity for this command
	// rather than mutating the user's repository configuration.
	if g.Remote != "" {
		if err := g.VerifyPrivate(ctx); err != nil {
			return fmt.Errorf("privacy verification before push failed: %w", err)
		}
		return g.commitAndPushRemoteAt(ctx, indexPath, message, objects, hashes, "")
	}
	for i, object := range objects {
		if err := g.run(ctx, "update-index", "--add", "--cacheinfo", "100644,"+hashes[i]+","+object.path); err != nil {
			return err
		}
	}
	if err := g.runWithIndex(ctx, indexPath,
		"-c", "user.name=cifrarium",
		"-c", "user.email=cifrarium@localhost",
		"commit", "-m", message,
	); err != nil {
		// A retry after a successful remote upload may have nothing new to
		// commit. Continue to the push so a prior local-only commit is still
		// delivered, and let the remote remain the idempotency boundary.
		if !strings.Contains(err.Error(), "nothing to commit") {
			return err
		}
	}
	return nil
}

// commitAndPushRemote creates the upload commit on the fetched remote branch,
// so unrelated local commits can never become ancestors sent by this upload.
func (g Git) commitAndPushRemote(ctx context.Context, indexPath, message string, objects []gitObject, hashes []string) error {
	return g.commitAndPushRemoteAt(ctx, indexPath, message, objects, hashes, "")
}

func (g Git) commitAndPushRemoteAt(ctx context.Context, indexPath, message string, objects []gitObject, hashes []string, expectedParent string) error {
	branch, parent, err := g.remoteHead(ctx)
	if err != nil {
		return err
	}
	if expectedParent != "" && parent != expectedParent {
		return fmt.Errorf("remote provider changed during history operation; inspect again")
	}
	if parent == "" {
		if err := g.runWithIndex(ctx, indexPath, "read-tree", "--empty"); err != nil {
			return err
		}
	} else if err := g.runWithIndex(ctx, indexPath, "read-tree", parent); err != nil {
		return err
	}
	unchanged := parent != ""
	for i, object := range objects {
		staged, err := g.outputWithIndex(ctx, indexPath, "ls-files", "--stage", "--", object.path)
		if err != nil {
			return err
		}
		fields := strings.Fields(string(staged))
		if len(fields) >= 2 && (fields[0] != "100644" || fields[1] != hashes[i]) {
			return fmt.Errorf("provider object already exists with different content: %s", object.path)
		}
		if len(fields) < 2 {
			unchanged = false
		}
		if err := g.runWithIndex(ctx, indexPath, "update-index", "--add", "--cacheinfo", "100644,"+hashes[i]+","+object.path); err != nil {
			return err
		}
	}
	if unchanged {
		return nil
	}
	tree, err := g.outputWithIndex(ctx, indexPath, "write-tree")
	if err != nil {
		return err
	}
	args := []string{"-c", "user.name=cifrarium", "-c", "user.email=cifrarium@localhost", "commit-tree", strings.TrimSpace(string(tree)), "-m", message}
	if parent != "" {
		args = []string{"-c", "user.name=cifrarium", "-c", "user.email=cifrarium@localhost", "commit-tree", strings.TrimSpace(string(tree)), "-p", parent, "-m", message}
	}
	commit, err := g.output(ctx, args...)
	if err != nil {
		return fmt.Errorf("create provider upload commit: %w", err)
	}
	return g.run(ctx, "push", g.Remote, strings.TrimSpace(string(commit))+":"+branch)
}

func (g Git) remoteHead(ctx context.Context) (string, string, error) {
	out, err := g.output(ctx, "ls-remote", "--symref", g.Remote, "HEAD")
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
		} else if fields[1] == "HEAD" {
			remoteHash = fields[0]
		}
	}
	if branch == "" {
		branchOutput, err := g.output(ctx, "symbolic-ref", "--quiet", "HEAD")
		if err != nil {
			return "", "", fmt.Errorf("cannot determine provider branch for initial upload: %w", err)
		}
		branch = strings.TrimSpace(string(branchOutput))
	}
	if !strings.HasPrefix(branch, "refs/heads/") || strings.ContainsAny(branch, " \t\r\n") {
		return "", "", fmt.Errorf("invalid remote provider branch")
	}
	if remoteHash == "" {
		return branch, "", nil
	}
	if err := g.run(ctx, "fetch", "--no-tags", g.Remote, branch); err != nil {
		return "", "", fmt.Errorf("fetch provider branch: %w", err)
	}
	fetched, err := g.output(ctx, "rev-parse", "--verify", "FETCH_HEAD^{commit}")
	if err != nil {
		return "", "", err
	}
	return branch, strings.TrimSpace(string(fetched)), nil
}

func (g Git) outputWithIndex(ctx context.Context, indexPath string, args ...string) ([]byte, error) {
	if err := g.validateRepositoryConfig(ctx); err != nil {
		return nil, err
	}
	cmd, cleanup, err := g.commandAtDir(ctx, "git", args...)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	cmd.Env = append(cmd.Env, "GIT_INDEX_FILE="+indexPath)
	return cmd.Output()
}

func (g Git) newUploadIndex(ctx context.Context) (string, func(), error) {
	indexDir, err := os.MkdirTemp("", "cifrarium-provider-index-")
	if err != nil {
		return "", func() {}, fmt.Errorf("create isolated provider index: %w", err)
	}
	indexPath := filepath.Join(indexDir, "index")
	cleanup := func() { _ = os.RemoveAll(indexDir) }
	if err := g.runWithIndex(ctx, indexPath, "read-tree", "HEAD"); err == nil {
		return indexPath, cleanup, nil
	} else {
		initializationErr := err
		headRef, refErr := g.output(ctx, "symbolic-ref", "--quiet", "HEAD")
		if refErr != nil {
			cleanup()
			return "", func() {}, initializationErr
		}
		_, refErr = g.output(ctx, "show-ref", "--verify", "--quiet", strings.TrimSpace(string(headRef)))
		var exitErr *exec.ExitError
		if ctx.Err() != nil || !errors.As(refErr, &exitErr) || exitErr.ExitCode() != 1 {
			cleanup()
			return "", func() {}, initializationErr
		}
		if err := g.runWithIndex(ctx, indexPath, "read-tree", "--empty"); err != nil {
			cleanup()
			return "", func() {}, err
		}
	}
	return indexPath, cleanup, nil
}

// Ensure initializes only the local repository and verifies an existing
// origin. It never creates a GitHub repository and never accepts credentials
// embedded in a remote URL.
func (g Git) Ensure(ctx context.Context) error {
	if g.Dir == "" {
		return fmt.Errorf("provider directory is required")
	}
	if info, err := os.Lstat(g.Dir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("provider directory symlink rejected")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(g.Dir, 0700); err != nil {
		return err
	}
	gitDir := filepath.Join(g.Dir, ".git")
	if info, err := os.Lstat(gitDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("provider .git symlink rejected")
	} else if os.IsNotExist(err) {
		if err := g.run(ctx, "init", "--initial-branch=main"); err != nil {
			return err
		}
		if err := g.run(ctx, "config", "user.name", "cifrarium"); err != nil {
			return err
		}
		if err := g.run(ctx, "config", "user.email", "cifrarium@localhost"); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if g.Remote == "" {
		return nil
	}
	if err := validateRemote(g.Remote); err != nil {
		return err
	}
	current, err := g.remoteURL(ctx)
	if err != nil {
		return g.run(ctx, "remote", "add", "origin", g.Remote)
	}
	if current != g.Remote {
		return fmt.Errorf("configured origin does not match requested GitHub remote")
	}
	return nil
}

func (g Git) remoteURL(ctx context.Context) (string, error) {
	out, err := g.output(ctx, "remote", "get-url", "origin")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func validateRemote(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil || u.Path == "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("remote must be an HTTPS GitHub URL without embedded credentials")
	}
	return nil
}

func githubRepoSlug(raw string) (string, error) {
	if err := validateRemote(raw); err != nil {
		return "", err
	}
	parts := strings.Split(strings.Trim(uPath(raw), "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("remote must identify one GitHub repository")
	}
	return strings.TrimSuffix(parts[0]+"/"+parts[1], ".git"), nil
}

func uPath(raw string) string {
	u, _ := url.Parse(raw)
	return u.Path
}

func validateID(id string) error {
	if id == "" || filepath.Base(id) != id || id == "." || id == ".." {
		return fmt.Errorf("invalid provider object id")
	}
	return nil
}
