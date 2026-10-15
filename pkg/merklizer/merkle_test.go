package merklizer

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestComputeRoot_Singleton(t *testing.T) {
	var l1 [32]byte
	l1[0] = 0xAA

	root, err := ComputeRoot([][32]byte{l1})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if root != l1 {
		t.Errorf("expected singleton root == leaf")
	}
}

func TestComputeRoot_Empty(t *testing.T) {
	_, err := ComputeRoot(nil)
	if !errors.Is(err, ErrEmptyLeaves) {
		t.Errorf("expected ErrEmptyLeaves, got %v", err)
	}
}

func TestComputeRoot_EvenLeaves(t *testing.T) {
	var l1, l2 [32]byte
	l1[0] = 0x01
	l2[0] = 0x02

	expected := HashNode(l1, l2)
	root, err := ComputeRoot([][32]byte{l1, l2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if root != expected {
		t.Errorf("expected %x, got %x", expected, root)
	}
}

func TestComputeRoot_OddPromotion(t *testing.T) {
	var l1, l2, l3 [32]byte
	l1[0] = 0x01
	l2[0] = 0x02
	l3[0] = 0x03

	parent01 := HashNode(l1, l2)
	expectedRoot := HashNode(parent01, l3)

	root, err := ComputeRoot([][32]byte{l1, l2, l3})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if root != expectedRoot {
		t.Errorf("expected %x, got %x", expectedRoot, root)
	}
}

func TestMerkleProof_GenerateAndVerify(t *testing.T) {
	testSizes := []int{1, 2, 3, 4, 5, 7, 8, 16, 17}

	for _, size := range testSizes {
		var leaves [][32]byte
		for i := 0; i < size; i++ {
			h := sha256.Sum256([]byte{byte(i + 1)})
			leaves = append(leaves, h)
		}

		root, err := ComputeRoot(leaves)
		if err != nil {
			t.Fatalf("size %d root error: %v", size, err)
		}

		for idx := 0; idx < size; idx++ {
			proof, err := GenerateProof(leaves, idx)
			if err != nil {
				t.Fatalf("size %d, idx %d proof err: %v", size, idx, err)
			}

			valid := VerifyProof(leaves[idx], proof, idx, root, size)
			if !valid {
				t.Errorf("size %d, idx %d: proof verification failed", size, idx)
			}

			// Verify bad leaf fails
			var fakeLeaf [32]byte
			fakeLeaf[0] = 0xFF
			if VerifyProof(fakeLeaf, proof, idx, root, size) {
				t.Errorf("size %d, idx %d: fake leaf should have failed", size, idx)
			}
		}
	}
}

func TestGenerateProof_Errors(t *testing.T) {
	_, err := GenerateProof(nil, 0)
	if !errors.Is(err, ErrEmptyLeaves) {
		t.Errorf("expected ErrEmptyLeaves, got %v", err)
	}

	leaves := [][32]byte{{0x01}}
	_, err = GenerateProof(leaves, -1)
	if !errors.Is(err, ErrIndexBounds) {
		t.Errorf("expected ErrIndexBounds, got %v", err)
	}

	_, err = GenerateProof(leaves, 2)
	if !errors.Is(err, ErrIndexBounds) {
		t.Errorf("expected ErrIndexBounds, got %v", err)
	}
}

func TestVerifyProof_EdgeCases(t *testing.T) {
	var leaf, root [32]byte
	leaf[0] = 1
	root[0] = 1

	if VerifyProof(leaf, nil, 0, root, 0) {
		t.Errorf("expected false for totalLeaves <= 0")
	}
	if VerifyProof(leaf, nil, -1, root, 1) {
		t.Errorf("expected false for index < 0")
	}
	if VerifyProof(leaf, nil, 2, root, 1) {
		t.Errorf("expected false for index >= totalLeaves")
	}
	if VerifyProof(leaf, [][32]byte{{0x02}}, 0, root, 1) {
		t.Errorf("expected false for non-empty proof on singleton")
	}
}

type mockGitTreeRunner struct {
	responses map[string]string
	errors    map[string]error
}

func (m *mockGitTreeRunner) RunGit(_ context.Context, _ string, args ...string) (string, error) {
	key := args[0]
	if len(args) > 1 {
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

func TestComputeTreeProvenance_MockHappyPath(t *testing.T) {
	ctx := context.Background()
	runner := &mockGitTreeRunner{
		responses: map[string]string{
			"rev-parse HEAD":        "commit_sha_123",
			"rev-parse commit_sha_123^{tree}": "tree_sha_456",
			"ls-tree -r":            "100644 blob blob_hash_1\tREADME.md\x00100644 blob blob_hash_2\tDESIGN.md\x00",
			"log -1":                "Justin\x00justin@legend.com\x001700000000\x00Justin\x00justin@legend.com\x001700000000\x00parent_sha",
		},
	}

	prov, err := ComputeTreeProvenance(ctx, runner, "/mock", "HEAD")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if prov.CommitHash != "commit_sha_123" {
		t.Errorf("expected commit_sha_123, got %s", prov.CommitHash)
	}
	if len(prov.Leaves) != 2 {
		t.Fatalf("expected 2 leaves, got %d", len(prov.Leaves))
	}
	// Verify sorted order: DESIGN.md before README.md
	if prov.Leaves[0].Path != "DESIGN.md" || prov.Leaves[1].Path != "README.md" {
		t.Errorf("expected sorted leaves, got %s, %s", prov.Leaves[0].Path, prov.Leaves[1].Path)
	}
}

func TestComputeTreeProvenance_EmptyTree(t *testing.T) {
	ctx := context.Background()
	runner := &mockGitTreeRunner{
		responses: map[string]string{
			"rev-parse HEAD":                  "commit_empty",
			"rev-parse commit_empty^{tree}":  "tree_empty",
			"ls-tree -r":                      "",
			"log -1":                          "Author\x00a@b.com\x00100\x00Author\x00a@b.com\x00100\x00",
		},
	}

	prov, err := ComputeTreeProvenance(ctx, runner, "/mock", "HEAD")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(prov.Leaves) != 0 {
		t.Errorf("expected 0 leaves, got %d", len(prov.Leaves))
	}
}

func TestComputeTreeProvenance_Failures(t *testing.T) {
	ctx := context.Background()
	runner := &mockGitTreeRunner{
		errors: map[string]error{
			"rev-parse HEAD": errors.New("cannot resolve commit"),
		},
	}

	_, err := ComputeTreeProvenance(ctx, runner, "/mock", "HEAD")
	if err == nil {
		t.Fatalf("expected error on commit resolve failure")
	}
}

func TestBytes32ToHex(t *testing.T) {
	var b [32]byte
	b[0] = 0xAA
	b[31] = 0xBB
	s := Bytes32ToHex(b)
	if len(s) != 64 {
		t.Errorf("expected 64 characters, got %d", len(s))
	}
}
