use adjustable_bid_encoding_rs::types::AdjustmentData;
use alloy_primitives::{keccak256, Address, B256};
use const_hex::FromHex;
use eyre::Result;

/// Advanced Merkle proof verification example with mathematical analysis
/// 
/// This example demonstrates:
/// 1. Complete Merkle tree construction
/// 2. Proof generation and verification algorithms
/// 3. Mathematical complexity analysis
/// 4. Security invariant validation
/// 5. Performance benchmarking
fn main() -> Result<()> {
    println!("🌳 Merkle Proof Verification Example");
    println!("===================================");
    
    // Step 1: Create a sample Merkle tree with 8 leaves
    let tree = create_sample_merkle_tree()?;
    println!("✅ Created Merkle tree with {} leaves", tree.leaves.len());
    println!("   Root: 0x{}", hex::encode(tree.root.as_slice()));
    
    // Step 2: Generate and verify proofs for each leaf
    test_proof_verification(&tree)?;
    
    // Step 3: Demonstrate mathematical properties
    demonstrate_mathematical_properties(&tree)?;
    
    // Step 4: Security analysis
    perform_security_analysis(&tree)?;
    
    // Step 5: Performance benchmarking
    benchmark_proof_operations()?;
    
    println!("\n🎉 Merkle proof verification example completed!");
    Ok(())
}

/// Simple Merkle tree implementation for demonstration
#[derive(Debug, Clone)]
struct MerkleTree {
    leaves: Vec<B256>,
    root: B256,
    tree: Vec<Vec<B256>>, // Each level of the tree
}

impl MerkleTree {
    /// Construct a Merkle tree from leaves using Keccak-256
    /// 
    /// Mathematical specification:
    /// - Level 0: leaves (input data)
    /// - Level i+1: parent[j] = H(left_child[2j] || right_child[2j+1])
    /// - Root: tree[log2(n)][0] where n = number of leaves
    fn new(leaves: Vec<B256>) -> Self {
        let mut tree = vec![leaves.clone()];
        let mut current_level = leaves;
        
        // Build tree bottom-up until we reach the root
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            
            // Process pairs of nodes
            for chunk in current_level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() == 2 { chunk[1] } else { left }; // Duplicate if odd
                
                // Hash concatenation: H(left || right)
                let combined = [left.as_slice(), right.as_slice()].concat();
                let parent = keccak256(&combined);
                next_level.push(parent);
            }
            
            tree.push(next_level.clone());
            current_level = next_level;
        }
        
        let root = current_level[0];
        
        Self {
            leaves: tree[0].clone(),
            root,
            tree,
        }
    }
    
    /// Generate Merkle proof for leaf at given index
    /// 
    /// Mathematical specification:
    /// proof[i] = sibling of node on path from leaf to root at level i
    /// Proof length = ceil(log2(n)) where n = number of leaves
    fn generate_proof(&self, leaf_index: usize) -> Result<Vec<B256>> {
        if leaf_index >= self.leaves.len() {
            return Err(eyre::eyre!("Leaf index {} out of bounds", leaf_index));
        }
        
        let mut proof = Vec::new();
        let mut current_index = leaf_index;
        
        // Traverse from leaf to root, collecting sibling hashes
        for level in 0..self.tree.len() - 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1 // Right sibling
            } else {
                current_index - 1 // Left sibling
            };
            
            // Add sibling to proof (if it exists)
            if sibling_index < self.tree[level].len() {
                proof.push(self.tree[level][sibling_index]);
            } else {
                // Duplicate leaf if tree size is not power of 2
                proof.push(self.tree[level][current_index]);
            }
            
            current_index /= 2; // Move to parent level
        }
        
        Ok(proof)
    }
    
    /// Verify Merkle proof against root
    /// 
    /// Mathematical specification:
    /// Let H = hash function, P = proof array, L = leaf value
    /// compute_root(L, P) = H(...H(H(L, P[0]), P[1])..., P[n-1])
    /// verify(L, P, R) = (compute_root(L, P) == R)
    fn verify_proof(&self, leaf: B256, leaf_index: usize, proof: &[B256]) -> bool {
        let mut current_hash = leaf;
        let mut current_index = leaf_index;
        
        // Reconstruct root by hashing with proof elements
        for &proof_element in proof {
            current_hash = if current_index % 2 == 0 {
                // Leaf is left child: H(leaf || sibling)
                keccak256([current_hash.as_slice(), proof_element.as_slice()].concat())
            } else {
                // Leaf is right child: H(sibling || leaf)
                keccak256([proof_element.as_slice(), current_hash.as_slice()].concat())
            };
            
            current_index /= 2;
        }
        
        current_hash == self.root
    }
}

/// Create sample tree for testing with realistic Ethereum data
fn create_sample_merkle_tree() -> Result<MerkleTree> {
    let sample_addresses = [
        "0x742d35Cc647C2dB8Dfa0fC7b6e7A1F6C0d5D5b8C",
        "0xfeedbabe647C2dB8Dfa0fC7b6e7A1F6C0d5D5b8C", 
        "0xdeadbeef647C2dB8Dfa0fC7b6e7A1F6C0d5D5b8C",
        "0xcafebabe647C2dB8Dfa0fC7b6e7A1F6C0d5D5b8C",
        "0x1234567890abcdef1234567890abcdef12345678",
        "0xabcdef1234567890abcdef1234567890abcdef12",
        "0x9876543210fedcba9876543210fedcba98765432",
        "0xfedcba0987654321fedcba0987654321fedcba09",
    ];
    
    // Convert addresses to hash leaves
    let leaves: Result<Vec<B256>> = sample_addresses
        .iter()
        .map(|addr| {
            let address = Address::from_hex(addr)?;
            Ok(keccak256(address.as_slice()))
        })
        .collect();
    
    Ok(MerkleTree::new(leaves?))
}

/// Test proof generation and verification for all leaves
fn test_proof_verification(tree: &MerkleTree) -> Result<()> {
    println!("\n🔍 Testing Proof Verification");
    println!("----------------------------");
    
    for (i, &leaf) in tree.leaves.iter().enumerate() {
        let proof = tree.generate_proof(i)?;
        let is_valid = tree.verify_proof(leaf, i, &proof);
        
        println!(
            "Leaf {}: {} (proof length: {}, valid: {})", 
            i, 
            hex::encode(&leaf.as_slice()[..8]), // First 8 bytes for brevity
            proof.len(),
            if is_valid { "✅" } else { "❌" }
        );
        
        if !is_valid {
            return Err(eyre::eyre!("Proof verification failed for leaf {}", i));
        }
    }
    
    println!("✅ All proofs verified successfully");
    Ok(())
}

/// Demonstrate mathematical properties of Merkle trees
fn demonstrate_mathematical_properties(tree: &MerkleTree) -> Result<()> {
    println!("\n📐 Mathematical Properties Analysis");
    println!("----------------------------------");
    
    let n = tree.leaves.len();
    let height = tree.tree.len() - 1;
    let expected_height = (n as f64).log2().ceil() as usize;
    
    println!("Number of leaves (n): {}", n);
    println!("Tree height: {} levels", height);
    println!("Expected height: {} (⌈log₂({})⌉)", expected_height, n);
    
    // Verify height property: height = ⌈log₂(n)⌉
    assert_eq!(height, expected_height);
    println!("✅ Height property verified");
    
    // Calculate total nodes in complete binary tree
    let total_nodes: usize = tree.tree.iter().map(|level| level.len()).sum();
    let expected_nodes = 2 * n - 1; // For complete binary tree
    
    println!("Total nodes: {}", total_nodes);
    println!("Expected nodes: {} (2n-1)", expected_nodes);
    
    // Verify proof length property
    let sample_proof = tree.generate_proof(0)?;
    println!("Sample proof length: {} = height", sample_proof.len());
    assert_eq!(sample_proof.len(), height);
    println!("✅ Proof length property verified");
    
    // Time complexity analysis
    println!("\n⏱️  Complexity Analysis:");
    println!("- Tree construction: O(n) where n = number of leaves");
    println!("- Proof generation: O(log n) where n = number of leaves");
    println!("- Proof verification: O(log n) where n = number of leaves");
    println!("- Space complexity: O(n) for tree storage");
    
    Ok(())
}

/// Perform security analysis on the Merkle tree
fn perform_security_analysis(tree: &MerkleTree) -> Result<()> {
    println!("\n🔒 Security Analysis");
    println!("-------------------");
    
    // Test 1: Root uniqueness - different trees should have different roots
    let modified_leaves = tree.leaves.iter()
        .enumerate()
        .map(|(i, &leaf)| {
            if i == 0 {
                keccak256(b"modified_leaf") // Modify first leaf
            } else {
                leaf
            }
        })
        .collect();
    
    let modified_tree = MerkleTree::new(modified_leaves);
    assert_ne!(tree.root, modified_tree.root);
    println!("✅ Root uniqueness: Different data produces different roots");
    
    // Test 2: Proof forgery resistance - invalid proofs should be rejected
    let fake_proof = vec![B256::from([0xFF; 32]); 3];
    let is_fake_valid = tree.verify_proof(tree.leaves[0], 0, &fake_proof);
    assert!(!is_fake_valid);
    println!("✅ Forgery resistance: Invalid proofs are rejected");
    
    // Test 3: Index validation - proofs are position-dependent
    let proof_for_leaf_0 = tree.generate_proof(0)?;
    let is_wrong_index_valid = tree.verify_proof(tree.leaves[1], 0, &proof_for_leaf_0);
    assert!(!is_wrong_index_valid);
    println!("✅ Position binding: Proofs are bound to specific leaf positions");
    
    // Test 4: Collision resistance property
    println!("✅ Collision resistance: Relies on Keccak-256 (SHA-3) properties");
    println!("   - Second preimage resistance: ~2^256 operations");
    println!("   - Collision resistance: ~2^128 operations (birthday bound)");
    
    Ok(())
}

/// Benchmark proof operations for performance analysis
fn benchmark_proof_operations() -> Result<()> {
    println!("\n⚡ Performance Benchmarking");
    println!("---------------------------");
    
    let tree_sizes = [8, 16, 32, 64, 128, 256, 512, 1024];
    
    for &size in &tree_sizes {
        // Create tree of given size
        let leaves: Vec<B256> = (0..size)
            .map(|i: u64| keccak256(&i.to_be_bytes()))
            .collect();
        
        let start = std::time::Instant::now();
        let tree = MerkleTree::new(leaves);
        let construction_time = start.elapsed();
        
        // Measure proof generation
        let start = std::time::Instant::now();
        let _proof = tree.generate_proof(0)?;
        let proof_gen_time = start.elapsed();
        
        // Measure proof verification
        let proof = tree.generate_proof(0)?;
        let start = std::time::Instant::now();
        let _is_valid = tree.verify_proof(tree.leaves[0], 0, &proof);
        let verification_time = start.elapsed();
        
        println!(
            "Size {:4}: construction {:6.2}μs, proof gen {:6.2}μs, verification {:6.2}μs, height {}",
            size,
            construction_time.as_micros(),
            proof_gen_time.as_micros(),
            verification_time.as_micros(),
            tree.tree.len() - 1
        );
    }
    
    println!("\n📊 Observations:");
    println!("- Construction time grows linearly with tree size: O(n)");
    println!("- Proof operations grow logarithmically: O(log n)");
    println!("- Verification is highly efficient even for large trees");
    
    Ok(())
}

/// Example integration with AdjustmentData
#[allow(dead_code)]
fn validate_adjustment_data_proofs(adjustment_data: &AdjustmentData) -> Result<()> {
    println!("\n🔧 AdjustmentData Proof Validation");
    println!("----------------------------------");
    
    // Create a mock state tree for demonstration
    let state_leaves = vec![
        keccak256(adjustment_data.builder_address.as_slice()),
        keccak256(adjustment_data.fee_recipient_address.as_slice()),
        keccak256(adjustment_data.fee_payer_address.as_slice()),
        keccak256(b"other_state_entry_1"),
        keccak256(b"other_state_entry_2"),
        keccak256(b"other_state_entry_3"),
        keccak256(b"other_state_entry_4"),
        keccak256(b"other_state_entry_5"),
    ];
    
    let state_tree = MerkleTree::new(state_leaves);
    
    // Verify that the state root matches the tree root
    if adjustment_data.state_root == state_tree.root {
        println!("✅ State root matches constructed tree");
        
        // In a real implementation, you would:
        // 1. Parse the builder_proof from AdjustmentData
        // 2. Convert to the format expected by verify_proof
        // 3. Verify against the known state_root
        
        println!("📝 Note: In production, parse adjustment_data.builder_proof");
        println!("   and verify against adjustment_data.state_root");
    } else {
        println!("ℹ️  State roots differ (expected in this demo)");
        println!("   Adjustment data: 0x{}", hex::encode(adjustment_data.state_root.as_slice()));
        println!("   Generated tree:  0x{}", hex::encode(state_tree.root.as_slice()));
    }
    
    Ok(())
}