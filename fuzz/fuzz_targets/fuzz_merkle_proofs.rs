#![no_main]

use libfuzzer_sys::fuzz_target;
use alloy_primitives::{keccak256, B256};
use arbitrary::Arbitrary;

/// Simple Merkle tree implementation for fuzzing
#[derive(Debug, Clone)]
struct SimpleMerkleTree {
    leaves: Vec<B256>,
    root: B256,
}

impl SimpleMerkleTree {
    fn new(leaves: Vec<B256>) -> Self {
        if leaves.is_empty() {
            return Self {
                leaves: vec![],
                root: B256::ZERO,
            };
        }
        
        let mut current_level = leaves.clone();
        
        // Build tree bottom-up
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            
            for chunk in current_level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() == 2 { chunk[1] } else { left };
                
                let combined = [left.as_slice(), right.as_slice()].concat();
                let parent = keccak256(&combined);
                next_level.push(parent);
            }
            
            current_level = next_level;
        }
        
        Self {
            leaves,
            root: current_level[0],
        }
    }
    
    fn generate_proof(&self, leaf_index: usize) -> Option<Vec<B256>> {
        if leaf_index >= self.leaves.len() || self.leaves.is_empty() {
            return None;
        }
        
        let mut proof = Vec::new();
        let mut current_level = self.leaves.clone();
        let mut current_index = leaf_index;
        
        while current_level.len() > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            
            if sibling_index < current_level.len() {
                proof.push(current_level[sibling_index]);
            } else {
                proof.push(current_level[current_index]);
            }
            
            // Build next level
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() == 2 { chunk[1] } else { left };
                
                let combined = [left.as_slice(), right.as_slice()].concat();
                let parent = keccak256(&combined);
                next_level.push(parent);
            }
            
            current_level = next_level;
            current_index /= 2;
        }
        
        Some(proof)
    }
    
    fn verify_proof(&self, leaf: B256, leaf_index: usize, proof: &[B256]) -> bool {
        if self.leaves.is_empty() {
            return false;
        }
        
        let mut current_hash = leaf;
        let mut current_index = leaf_index;
        
        for &proof_element in proof {
            current_hash = if current_index % 2 == 0 {
                keccak256([current_hash.as_slice(), proof_element.as_slice()].concat())
            } else {
                keccak256([proof_element.as_slice(), current_hash.as_slice()].concat())
            };
            
            current_index /= 2;
        }
        
        current_hash == self.root
    }
}

/// Fuzz target for Merkle proof generation and verification
/// 
/// This fuzzer tests:
/// 1. Merkle tree construction with arbitrary leaves
/// 2. Proof generation for all possible indices
/// 3. Proof verification correctness
/// 4. Malformed proof handling
/// 5. Edge cases (empty trees, single leaf, etc.)
fuzz_target!(|data: &[u8]| {
    if let Ok(mut unstructured) = arbitrary::Unstructured::new(data) {
        
        // Test 1: Merkle tree construction and basic operations
        if let Ok(num_leaves) = unstructured.int_in_range(0..=32) {
            let mut leaves = Vec::new();
            
            // Generate leaves
            for _ in 0..num_leaves {
                if let Ok(leaf_bytes) = unstructured.arbitrary::<[u8; 32]>() {
                    leaves.push(B256::from(leaf_bytes));
                }
            }
            
            // Don't proceed with empty leaves for most tests
            if leaves.is_empty() {
                // Test empty tree edge case
                let empty_tree = SimpleMerkleTree::new(vec![]);
                assert_eq!(empty_tree.root, B256::ZERO);
                assert_eq!(empty_tree.generate_proof(0), None);
                return;
            }
            
            // Create tree
            let tree = SimpleMerkleTree::new(leaves.clone());
            
            // Test proof generation and verification for all valid indices
            for (i, &leaf) in leaves.iter().enumerate() {
                if let Some(proof) = tree.generate_proof(i) {
                    // Verify the proof
                    let is_valid = tree.verify_proof(leaf, i, &proof);
                    assert!(is_valid, "Generated proof should be valid");
                    
                    // Test proof depth bound (should be <= log2(n))
                    let expected_max_depth = if leaves.len() == 1 { 
                        0 
                    } else { 
                        (leaves.len() as f64).log2().ceil() as usize 
                    };
                    assert!(proof.len() <= expected_max_depth + 1, 
                           "Proof depth {} exceeds expected maximum {}", 
                           proof.len(), expected_max_depth + 1);
                    
                    // Test with wrong leaf (should fail)
                    let wrong_leaf = keccak256(b"wrong_leaf");
                    if wrong_leaf != leaf {
                        let is_invalid = tree.verify_proof(wrong_leaf, i, &proof);
                        assert!(!is_invalid, "Proof with wrong leaf should be invalid");
                    }
                    
                    // Test with wrong index (should fail)
                    if leaves.len() > 1 {
                        let wrong_index = (i + 1) % leaves.len();
                        let is_invalid = tree.verify_proof(leaf, wrong_index, &proof);
                        assert!(!is_invalid, "Proof with wrong index should be invalid");
                    }
                }
            }
            
            // Test invalid indices
            assert_eq!(tree.generate_proof(leaves.len()), None);
            assert_eq!(tree.generate_proof(leaves.len() + 100), None);
        }
        
        // Test 2: Arbitrary proof verification (malformed proofs)
        if let Ok(leaf_bytes) = unstructured.arbitrary::<[u8; 32]>() {
            if let Ok(num_proof_elements) = unstructured.int_in_range(0..=20) {
                let leaf = B256::from(leaf_bytes);
                let mut proof = Vec::new();
                
                // Generate arbitrary proof elements
                for _ in 0..num_proof_elements {
                    if let Ok(proof_element_bytes) = unstructured.arbitrary::<[u8; 32]>() {
                        proof.push(B256::from(proof_element_bytes));
                    }
                }
                
                // Create a small tree for testing
                let test_leaves = vec![
                    B256::from([1u8; 32]),
                    B256::from([2u8; 32]),
                    B256::from([3u8; 32]),
                    B256::from([4u8; 32]),
                ];
                let test_tree = SimpleMerkleTree::new(test_leaves);
                
                // Test arbitrary proof (should not panic)
                if let Ok(leaf_index) = unstructured.int_in_range(0..=10) {
                    let _ = test_tree.verify_proof(leaf, leaf_index, &proof);
                }
            }
        }
        
        // Test 3: Edge cases
        if data.len() > 50 {
            // Single leaf tree
            let single_leaf = B256::from([42u8; 32]);
            let single_tree = SimpleMerkleTree::new(vec![single_leaf]);
            
            if let Some(proof) = single_tree.generate_proof(0) {
                assert_eq!(proof.len(), 0, "Single leaf should have empty proof");
                assert!(single_tree.verify_proof(single_leaf, 0, &proof));
            }
            
            // Two leaf tree
            let two_leaves = vec![B256::from([1u8; 32]), B256::from([2u8; 32])];
            let two_tree = SimpleMerkleTree::new(two_leaves.clone());
            
            for (i, &leaf) in two_leaves.iter().enumerate() {
                if let Some(proof) = two_tree.generate_proof(i) {
                    assert_eq!(proof.len(), 1, "Two leaf tree should have proof length 1");
                    assert!(two_tree.verify_proof(leaf, i, &proof));
                }
            }
        }
        
        // Test 4: Consistency properties
        if let Ok(num_leaves) = unstructured.int_in_range(2..=16) {
            let mut leaves = Vec::new();
            
            for i in 0..num_leaves {
                leaves.push(B256::from([i as u8; 32]));
            }
            
            let tree = SimpleMerkleTree::new(leaves.clone());
            
            // Test that all leaves can be proven
            for (i, &leaf) in leaves.iter().enumerate() {
                if let Some(proof) = tree.generate_proof(i) {
                    assert!(tree.verify_proof(leaf, i, &proof));
                    
                    // Test that modifying any proof element breaks verification
                    if !proof.is_empty() {
                        let mut corrupted_proof = proof.clone();
                        corrupted_proof[0] = keccak256(b"corrupted");
                        
                        if corrupted_proof[0] != proof[0] {
                            assert!(!tree.verify_proof(leaf, i, &corrupted_proof));
                        }
                    }
                }
            }
            
            // Test root uniqueness - different leaf sets should produce different roots
            let mut modified_leaves = leaves.clone();
            if !modified_leaves.is_empty() {
                modified_leaves[0] = keccak256(b"modified");
                let modified_tree = SimpleMerkleTree::new(modified_leaves);
                
                if modified_tree.leaves != tree.leaves {
                    assert_ne!(modified_tree.root, tree.root, 
                              "Different leaf sets should produce different roots");
                }
            }
        }
        
        // Test 5: Performance and memory safety with larger trees
        if data.len() > 100 && data.len() <= 500 {
            if let Ok(num_leaves) = unstructured.int_in_range(50..=100) {
                let mut leaves = Vec::new();
                
                // Create larger tree
                for i in 0..num_leaves {
                    let mut leaf_data = [0u8; 32];
                    leaf_data[0] = (i / 256) as u8;
                    leaf_data[1] = (i % 256) as u8;
                    leaves.push(B256::from(leaf_data));
                }
                
                let large_tree = SimpleMerkleTree::new(leaves.clone());
                
                // Test a few random proofs
                if let Ok(test_indices) = (0..3)
                    .map(|_| unstructured.int_in_range(0..num_leaves))
                    .collect::<Result<Vec<_>, _>>() {
                    
                    for &index in &test_indices {
                        if let Some(proof) = large_tree.generate_proof(index) {
                            assert!(large_tree.verify_proof(leaves[index], index, &proof));
                            
                            // Verify proof depth is reasonable
                            let max_expected_depth = (num_leaves as f64).log2().ceil() as usize + 1;
                            assert!(proof.len() <= max_expected_depth);
                        }
                    }
                }
            }
        }
    }
});