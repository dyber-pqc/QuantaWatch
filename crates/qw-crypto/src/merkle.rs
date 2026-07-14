use crate::hashing::sha3_256;

/// A simple append-only Merkle tree for audit chain batches.
pub struct MerkleTree;

impl MerkleTree {
    /// Compute the Merkle root from a list of leaf hashes.
    /// If the number of leaves is odd, the last leaf is duplicated.
    pub fn compute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.is_empty() {
            return [0u8; 32];
        }
        if leaves.len() == 1 {
            return leaves[0];
        }

        let mut current_level: Vec<[u8; 32]> = leaves.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));

            for chunk in current_level.chunks(2) {
                let combined = if chunk.len() == 2 {
                    [chunk[0].as_slice(), chunk[1].as_slice()].concat()
                } else {
                    // Odd leaf: duplicate it
                    [chunk[0].as_slice(), chunk[0].as_slice()].concat()
                };
                next_level.push(sha3_256(&combined));
            }

            current_level = next_level;
        }

        current_level[0]
    }

    /// Generate a Merkle proof for a leaf at the given index.
    pub fn compute_proof(leaves: &[[u8; 32]], index: usize) -> MerkleProof {
        let mut proof = Vec::new();
        let mut current_level: Vec<[u8; 32]> = leaves.to_vec();
        let mut idx = index;

        while current_level.len() > 1 {
            // Determine sibling
            let sibling_idx = if idx.is_multiple_of(2) {
                if idx + 1 < current_level.len() { idx + 1 } else { idx }
            } else {
                idx - 1
            };

            proof.push(ProofNode {
                hash: current_level[sibling_idx],
                is_left: !idx.is_multiple_of(2),
            });

            // Compute next level
            let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
            for chunk in current_level.chunks(2) {
                let combined = if chunk.len() == 2 {
                    [chunk[0].as_slice(), chunk[1].as_slice()].concat()
                } else {
                    [chunk[0].as_slice(), chunk[0].as_slice()].concat()
                };
                next_level.push(sha3_256(&combined));
            }

            current_level = next_level;
            idx /= 2;
        }

        MerkleProof {
            leaf: leaves[index],
            proof,
            root: current_level[0],
        }
    }

    /// Verify a Merkle proof.
    pub fn verify_proof(proof: &MerkleProof) -> bool {
        let mut current = proof.leaf;

        for node in &proof.proof {
            let combined = if node.is_left {
                [node.hash.as_slice(), current.as_slice()].concat()
            } else {
                [current.as_slice(), node.hash.as_slice()].concat()
            };
            current = sha3_256(&combined);
        }

        current == proof.root
    }
}

/// A node in a Merkle proof path.
#[derive(Debug, Clone)]
pub struct ProofNode {
    pub hash: [u8; 32],
    pub is_left: bool,
}

/// A Merkle inclusion proof.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub leaf: [u8; 32],
    pub proof: Vec<ProofNode>,
    pub root: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::sha3_256;

    #[test]
    fn test_empty_tree() {
        let root = MerkleTree::compute_root(&[]);
        assert_eq!(root, [0u8; 32]);
    }

    #[test]
    fn test_single_leaf() {
        let leaf = sha3_256(b"leaf0");
        let root = MerkleTree::compute_root(&[leaf]);
        assert_eq!(root, leaf);
    }

    #[test]
    fn test_two_leaves() {
        let l0 = sha3_256(b"leaf0");
        let l1 = sha3_256(b"leaf1");
        let root = MerkleTree::compute_root(&[l0, l1]);
        let expected = sha3_256(&[l0.as_slice(), l1.as_slice()].concat());
        assert_eq!(root, expected);
    }

    #[test]
    fn test_four_leaves() {
        let leaves: Vec<[u8; 32]> = (0..4).map(|i| sha3_256(format!("leaf{i}").as_bytes())).collect();
        let root = MerkleTree::compute_root(&leaves);
        // Should be deterministic
        let root2 = MerkleTree::compute_root(&leaves);
        assert_eq!(root, root2);
    }

    #[test]
    fn test_odd_leaves() {
        let leaves: Vec<[u8; 32]> = (0..5).map(|i| sha3_256(format!("leaf{i}").as_bytes())).collect();
        let root = MerkleTree::compute_root(&leaves);
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn test_proof_valid() {
        let leaves: Vec<[u8; 32]> = (0..8).map(|i| sha3_256(format!("leaf{i}").as_bytes())).collect();
        for i in 0..8 {
            let proof = MerkleTree::compute_proof(&leaves, i);
            assert!(MerkleTree::verify_proof(&proof), "proof failed for leaf {i}");
        }
    }

    #[test]
    fn test_proof_odd_leaves() {
        let leaves: Vec<[u8; 32]> = (0..5).map(|i| sha3_256(format!("leaf{i}").as_bytes())).collect();
        for i in 0..5 {
            let proof = MerkleTree::compute_proof(&leaves, i);
            assert!(MerkleTree::verify_proof(&proof), "proof failed for leaf {i}");
        }
    }

    #[test]
    fn test_tampered_proof_fails() {
        let leaves: Vec<[u8; 32]> = (0..4).map(|i| sha3_256(format!("leaf{i}").as_bytes())).collect();
        let mut proof = MerkleTree::compute_proof(&leaves, 0);
        proof.leaf = sha3_256(b"tampered");
        assert!(!MerkleTree::verify_proof(&proof));
    }
}
