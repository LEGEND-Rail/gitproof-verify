package merklizer

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/legendrail/gitproof-verify/pkg/gitenv"
)

const (
	DomainGitLeaf = "gitproof.leaf.v1"
	DomainRoot    = "gitproof.root.v1"
)

// GitFileLeaf represents a single file's cryptographic commitment in the tree.
type GitFileLeaf struct {
	Mode     string // e.g. "100644"
	Type     string // "blob"
	Object   string // git blob hash
	Path     string // relative repo path
	LeafHash [32]byte
}

// ComputeGitFileLeaf computes a deterministic RFC 6962 leaf hash for a repository file.
func ComputeGitFileLeaf(mode, objectType, objectHash, path string) GitFileLeaf {
	h := sha256.New()
	h.Write([]byte(DomainGitLeaf))
	h.Write([]byte{0x00})
	h.Write([]byte(mode))
	h.Write([]byte{0x00})
	h.Write([]byte(objectType))
	h.Write([]byte{0x00})
	h.Write([]byte(objectHash))
	h.Write([]byte{0x00})
	h.Write([]byte(path))

	inner := h.Sum(nil)
	leafHash := HashLeaf(inner)

	return GitFileLeaf{
		Mode:     mode,
		Type:     objectType,
		Object:   objectHash,
		Path:     path,
		LeafHash: leafHash,
	}
}

// TreeProvenance contains the deterministic Merkle root and leaves computed over a Git commit tree.
type TreeProvenance struct {
	CommitHash        string
	TreeHash          string
	Leaves            []GitFileLeaf
	TreeMerkleRoot    [32]byte
	OverallMerkleRoot [32]byte // Binds TreeMerkleRoot with author, committer, and parent metadata
}

// ComputeTreeProvenance traverses the Git tree at commitHash and computes the bit-for-bit Merkle root.
func ComputeTreeProvenance(ctx context.Context, runner gitenv.GitRunner, repoRoot, commitHash string) (*TreeProvenance, error) {
	if runner == nil {
		runner = gitenv.ExecRunner{}
	}

	// 1. Resolve commit and tree hash
	actualCommit, err := runner.RunGit(ctx, repoRoot, "rev-parse", commitHash)
	if err != nil {
		return nil, fmt.Errorf("merklizer: failed to resolve commit %s: %w", commitHash, err)
	}

	treeHash, err := runner.RunGit(ctx, repoRoot, "rev-parse", fmt.Sprintf("%s^{tree}", actualCommit))
	if err != nil {
		return nil, fmt.Errorf("merklizer: failed to resolve tree for %s: %w", actualCommit, err)
	}

	// 2. List all objects recursively: git ls-tree -r -z <treeHash>
	lsOutput, err := runner.RunGit(ctx, repoRoot, "ls-tree", "-r", "-z", treeHash)
	if err != nil {
		return nil, fmt.Errorf("merklizer: ls-tree failed: %w", err)
	}

	var leaves []GitFileLeaf
	if len(lsOutput) > 0 {
		records := strings.Split(lsOutput, "\x00")
		for _, rec := range records {
			if len(strings.TrimSpace(rec)) == 0 {
				continue
			}
			// Format: <mode> SP <type> SP <object> TAB <file>
			tabParts := strings.SplitN(rec, "\t", 2)
			if len(tabParts) != 2 {
				continue
			}
			path := tabParts[1]
			metaParts := strings.Fields(tabParts[0])
			if len(metaParts) < 3 {
				continue
			}
			mode := metaParts[0]
			objType := metaParts[1]
			objHash := metaParts[2]

			leaf := ComputeGitFileLeaf(mode, objType, objHash, path)
			leaves = append(leaves, leaf)
		}
	}

	// Sort leaves strictly in lexicographical order by Path
	sort.Slice(leaves, func(i, j int) bool {
		return leaves[i].Path < leaves[j].Path
	})

	var leafHashes [][32]byte
	for _, l := range leaves {
		leafHashes = append(leafHashes, l.LeafHash)
	}

	// If repository has no files (empty initial tree), generate sentinel root
	var treeMerkleRoot [32]byte
	if len(leafHashes) == 0 {
		h := sha256.New()
		h.Write([]byte("gitproof.empty.tree.v1"))
		copy(treeMerkleRoot[:], h.Sum(nil))
	} else {
		root, err := ComputeRoot(leafHashes)
		if err != nil {
			return nil, fmt.Errorf("merklizer: failed to compute root: %w", err)
		}
		treeMerkleRoot = root
	}

	// 3. Bind with Commit Metadata to form OverallMerkleRoot
	// Reads commit log: author, committer, timestamps, parents
	logFormat := "%an%x00%ae%x00%at%x00%cn%x00%ce%x00%ct%x00%P"
	metaRaw, err := runner.RunGit(ctx, repoRoot, "log", "-1", fmt.Sprintf("--format=%s", logFormat), actualCommit)
	if err != nil {
		return nil, fmt.Errorf("merklizer: failed to read commit log for %s: %w", actualCommit, err)
	}

	overallHasher := sha256.New()
	overallHasher.Write([]byte(DomainRoot))
	overallHasher.Write([]byte{0x00})
	overallHasher.Write(treeMerkleRoot[:])
	overallHasher.Write([]byte{0x00})
	overallHasher.Write([]byte(metaRaw))
	var overallRoot [32]byte
	copy(overallRoot[:], overallHasher.Sum(nil))

	return &TreeProvenance{
		CommitHash:        actualCommit,
		TreeHash:          treeHash,
		Leaves:            leaves,
		TreeMerkleRoot:    treeMerkleRoot,
		OverallMerkleRoot: overallRoot,
	}, nil
}
