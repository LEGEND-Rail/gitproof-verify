package gitenv

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var (
	ErrNotGitRepository = errors.New("gitenv: not a git repository")
	ErrDirtyWorkingTree = errors.New("gitenv: working tree contains uncommitted changes")
	ErrDetachedHead     = errors.New("gitenv: repository is in detached HEAD state")
)

// RepositoryState captures the cryptographic and author metadata of a Git repository at HEAD.
type RepositoryState struct {
	RepoRoot       string
	Branch         string
	CommitHash     string
	TreeHash       string
	ParentHashes   []string
	AuthorName     string
	AuthorEmail    string
	AuthorDate     time.Time
	CommitterName  string
	CommitterEmail string
	CommitterDate  time.Time
	IsClean        bool
}

// GitRunner abstracts command execution for testability.
type GitRunner interface {
	RunGit(ctx context.Context, dir string, args ...string) (string, error)
}

// ExecRunner executes real git commands using os/exec.
type ExecRunner struct{}

func (ExecRunner) RunGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// Inspect reads and validates repository state for the current working directory.
func Inspect(ctx context.Context, runner GitRunner, dir string) (*RepositoryState, error) {
	if runner == nil {
		runner = ExecRunner{}
	}

	// 1. Find root directory
	root, err := runner.RunGit(ctx, dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, ErrNotGitRepository
	}

	// 2. Check clean status
	statusOutput, err := runner.RunGit(ctx, root, "status", "--porcelain")
	if err != nil {
		return nil, fmt.Errorf("gitenv: status check failed: %w", err)
	}
	isClean := len(strings.TrimSpace(statusOutput)) == 0

	// 3. Current branch
	branch, _ := runner.RunGit(ctx, root, "rev-parse", "--abbrev-ref", "HEAD")

	// 4. Commit and Tree hash
	commitHash, err := runner.RunGit(ctx, root, "rev-parse", "HEAD")
	if err != nil {
		return nil, fmt.Errorf("gitenv: failed to resolve HEAD: %w", err)
	}

	treeHash, err := runner.RunGit(ctx, root, "rev-parse", "HEAD^{tree}")
	if err != nil {
		return nil, fmt.Errorf("gitenv: failed to resolve tree hash: %w", err)
	}

	// 5. Parent hashes
	parentsRaw, _ := runner.RunGit(ctx, root, "log", "-1", "--format=%P", commitHash)
	var parentHashes []string
	if strings.TrimSpace(parentsRaw) != "" {
		parentHashes = strings.Fields(parentsRaw)
	}

	// 6. Metadata formatting: author name, email, unix timestamp
	format := "%an%x00%ae%x00%at%x00%cn%x00%ce%x00%ct"
	metaRaw, err := runner.RunGit(ctx, root, "log", "-1", fmt.Sprintf("--format=%s", format), commitHash)
	if err != nil {
		return nil, fmt.Errorf("gitenv: failed to read commit metadata: %w", err)
	}

	parts := strings.Split(metaRaw, "\x00")
	if len(parts) < 6 {
		return nil, fmt.Errorf("gitenv: invalid commit metadata format")
	}

	authorUnix, _ := strconv.ParseInt(parts[2], 10, 64)
	committerUnix, _ := strconv.ParseInt(parts[5], 10, 64)

	return &RepositoryState{
		RepoRoot:       root,
		Branch:         branch,
		CommitHash:     commitHash,
		TreeHash:       treeHash,
		ParentHashes:   parentHashes,
		AuthorName:     parts[0],
		AuthorEmail:    parts[1],
		AuthorDate:     time.Unix(authorUnix, 0).UTC(),
		CommitterName:  parts[3],
		CommitterEmail: parts[4],
		CommitterDate:  time.Unix(committerUnix, 0).UTC(),
		IsClean:        isClean,
	}, nil
}
