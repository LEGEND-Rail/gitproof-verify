package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLI_Version(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-version"}, &stdout, &stderr, nil)
	if code != 0 {
		t.Fatalf("expected code 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "gproof-verify") {
		t.Errorf("expected version output, got: %s", stdout.String())
	}
}

func TestCLI_Help(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-help"}, &stdout, &stderr, nil)
	if code != 0 {
		t.Fatalf("expected code 0, got %d", code)
	}
}

func TestCLI_MissingFile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-proof", "non-existent-proof.json"}, &stdout, &stderr, nil)
	if code != 1 {
		t.Fatalf("expected code 1 on missing proof file, got %d", code)
	}
	if !strings.Contains(stderr.String(), "Error reading proof file") {
		t.Errorf("expected error message in stderr, got: %s", stderr.String())
	}
}
