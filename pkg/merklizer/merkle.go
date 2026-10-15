package merklizer

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

const (
	// RFC 6962 Domain Separation Prefixes
	LeafPrefix byte = 0x00
	NodePrefix byte = 0x01
)

var (
	ErrEmptyLeaves  = errors.New("merklizer: cannot compute root of empty leaf set")
	ErrIndexBounds  = errors.New("merklizer: leaf index out of bounds")
	ErrInvalidProof = errors.New("merklizer: invalid proof")
)

// HashNode computes keccak256 or sha256 of 0x01 || left || right following RFC 6962.
func HashNode(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{NodePrefix})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// HashLeaf computes sha256 of 0x00 || data following RFC 6962.
func HashLeaf(data []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{LeafPrefix})
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ComputeRoot builds a Merkle tree from leaves and returns the root hash.
// Odd node at a level is PROMOTED unchanged (never duplicated), closing CVE-2012-2459.
func ComputeRoot(leaves [][32]byte) ([32]byte, error) {
	n := len(leaves)
	if n == 0 {
		return [32]byte{}, ErrEmptyLeaves
	}
	if n == 1 {
		return leaves[0], nil
	}

	// Work on a copy of the slice
	current := make([][32]byte, n)
	copy(current, leaves)

	for len(current) > 1 {
		var next [][32]byte
		for i := 0; i < len(current); i += 2 {
			if i+1 == len(current) {
				// Promote odd node unchanged
				next = append(next, current[i])
			} else {
				next = append(next, HashNode(current[i], current[i+1]))
			}
		}
		current = next
	}

	return current[0], nil
}

// GenerateProof computes the Merkle audit path for the leaf at index.
func GenerateProof(leaves [][32]byte, index int) ([][32]byte, error) {
	n := len(leaves)
	if n == 0 {
		return nil, ErrEmptyLeaves
	}
	if index < 0 || index >= n {
		return nil, ErrIndexBounds
	}
	if n == 1 {
		return nil, nil // Singleton has empty proof path
	}

	var proof [][32]byte
	current := make([][32]byte, n)
	copy(current, leaves)
	idx := index

	for len(current) > 1 {
		var next [][32]byte
		for i := 0; i < len(current); i += 2 {
			if i+1 == len(current) {
				// Odd node promoted unchanged
				if i == idx {
					// Sibling does not exist at this level; nothing added to proof
					idx = len(next)
				}
				next = append(next, current[i])
			} else {
				if i == idx {
					proof = append(proof, current[i+1])
					idx = len(next)
				} else if i+1 == idx {
					proof = append(proof, current[i])
					idx = len(next)
				}
				next = append(next, HashNode(current[i], current[i+1]))
			}
		}
		current = next
	}

	return proof, nil
}

// VerifyProof verifies that leaf belongs to root at given index using proof path.
func VerifyProof(leaf [32]byte, proof [][32]byte, index int, root [32]byte, totalLeaves int) bool {
	if totalLeaves <= 0 || index < 0 || index >= totalLeaves {
		return false
	}
	if totalLeaves == 1 {
		return leaf == root && len(proof) == 0
	}

	current := leaf
	idx := index
	levelSize := totalLeaves
	proofIdx := 0

	for levelSize > 1 {
		isOdd := (levelSize % 2) == 1
		isLast := idx == levelSize-1

		if isOdd && isLast {
			// Node was promoted without sibling
			idx = idx / 2
		} else {
			if proofIdx >= len(proof) {
				return false
			}
			sibling := proof[proofIdx]
			proofIdx++

			if idx%2 == 0 {
				current = HashNode(current, sibling)
			} else {
				current = HashNode(sibling, current)
			}
			idx = idx / 2
		}

		levelSize = (levelSize + 1) / 2
	}

	if proofIdx != len(proof) {
		return false
	}

	return current == root
}

// StringToHex returns standard 64-character lowercase hex encoding.
func Bytes32ToHex(b [32]byte) string {
	return fmt.Sprintf("%x", b[:])
}
