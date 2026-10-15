package gitenv

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

type mockGitRunner struct {
	responses map[string]string
	errors    map[string]error
}

func (m *mockGitRunner) RunGit(_ context.Context, _ string, args ...string) (string, error) {
	key := args[0]
	if len(args) > 1 && args[0] == "rev-parse" {
		key = args[0] + " " + args[1]
	}
	if err, ok := m.errors[key]; ok {
		return "", err
	}
	if resp, ok := m.responses[key]; ok {
		return resp, nil
	}
	return "", nil
}

func TestInspect_MockHappyPath(t *testing.T) {
	ctx := context.Background()
	mock := &mockGitRunner{
		responses: map[string]string{
			"rev-parse --show-toplevel": "/mock/repo",
			"status":                    "",
			"rev-parse --abbrev-ref":    "main",
			"rev-parse HEAD":            "abcdef1234567890",
			"rev-parse HEAD^{tree}":     "123456abcdef7890",
			"log":                       "Justin Grant\x00justin@legendrail.com\x001700000000\x00Justin Grant\x00justin@legendrail.com\x001700000000",
		},
		errors: map[string]error{},
	}

	state, err := Inspect(ctx, mock, "/mock/repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !state.IsClean {
		t.Errorf("expected clean working tree")
	}
	if state.CommitHash != "abcdef1234567890" {
		t.Errorf("expected commit hash abcdef1234567890, got %s", state.CommitHash)
	}
	if state.AuthorName != "Justin Grant" {
		t.Errorf("expected author Justin Grant, got %s", state.AuthorName)
	}
	if state.AuthorDate.Unix() != 1700000000 {
		t.Errorf("expected unix timestamp 1700000000, got %d", state.AuthorDate.Unix())
	}
}

func TestInspect_NotGitRepository(t *testing.T) {
	ctx := context.Background()
	mock := &mockGitRunner{
		errors: map[string]error{
			"rev-parse --show-toplevel": errors.New("fatal: not a git repository"),
		},
	}

	_, err := Inspect(ctx, mock, "/nonexistent")
	if !errors.Is(err, ErrNotGitRepository) {
		t.Errorf("expected ErrNotGitRepository, got %v", err)
	}
}

func TestInspect_StatusFailure(t *testing.T) {
	ctx := context.Background()
	mock := &mockGitRunner{
		responses: map[string]string{
			"rev-parse --show-toplevel": "/mock/repo",
		},
		errors: map[string]error{
			"status": errors.New("failed status"),
		},
	}

	_, err := Inspect(ctx, mock, "/mock/repo")
	if err == nil {
		t.Fatalf("expected error on status failure")
	}
}

func TestInspect_HeadResolutionFailure(t *testing.T) {
	ctx := context.Background()
	mock := &mockGitRunner{
		responses: map[string]string{
			"rev-parse --show-toplevel": "/mock/repo",
			"status":                    "",
		},
		errors: map[string]error{
			"rev-parse HEAD": errors.New("cannot resolve HEAD"),
		},
	}

	_, err := Inspect(ctx, mock, "/mock/repo")
	if err == nil {
		t.Fatalf("expected error on HEAD resolution failure")
	}
}

func TestInspect_TreeResolutionFailure(t *testing.T) {
	ctx := context.Background()
	mock := &mockGitRunner{
		responses: map[string]string{
			"rev-parse --show-toplevel": "/mock/repo",
			"status":                    "",
			"rev-parse HEAD":            "abcdef",
		},
		errors: map[string]error{
			"rev-parse HEAD^{tree}": errors.New("cannot resolve tree"),
		},
	}

	_, err := Inspect(ctx, mock, "/mock/repo")
	if err == nil {
		t.Fatalf("expected error on tree resolution failure")
	}
}

func TestInspect_InvalidMetadata(t *testing.T) {
	ctx := context.Background()
	mock := &mockGitRunner{
		responses: map[string]string{
			"rev-parse --show-toplevel": "/mock/repo",
			"status":                    "",
			"rev-parse HEAD":            "abcdef",
			"rev-parse HEAD^{tree}":     "tree123",
			"log":                       "bad_metadata_without_delimiters",
		},
	}

	_, err := Inspect(ctx, mock, "/mock/repo")
	if err == nil {
		t.Fatalf("expected error on invalid metadata")
	}
}

func TestInspect_RealExecution(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cwd, err := os.Getwd()
	if err != nil {
		t.Skip("cannot determine cwd")
	}

	state, err := Inspect(ctx, nil, cwd)
	if err != nil {
		t.Fatalf("failed real inspect: %v", err)
	}

	if state.CommitHash == "" {
		t.Errorf("expected non-empty commit hash")
	}
	if state.TreeHash == "" {
		t.Errorf("expected non-empty tree hash")
	}
}
