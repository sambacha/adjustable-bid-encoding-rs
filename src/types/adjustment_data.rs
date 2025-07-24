use alloy_primitives::{Address, B256};
use crate::invariants::*;

/// Adjustment data containing cryptographic proofs for block submission validation.
/// 
/// This structure holds Merkle proofs and commitments required to verify the integrity
/// of adjustable block submissions. All proofs must satisfy the following mathematical invariants:
/// 
/// ## Mathematical Properties
/// 
/// ### State Root Invariant
/// ```text
/// state_root = merkle_root(state_trie)
/// verify_merkle_proof(builder_proof, builder_address, state_root) = true
/// ```
/// 
/// ### Transaction Root Invariant
/// ```text
/// transactions_root = merkle_root(transactions[])
/// ∀i: tx_hash[i] = keccak256(transactions[i])
/// ```
/// 
/// ### Receipt Root Invariant
/// ```text
/// receipts_root = merkle_root(receipts[])
/// ∀i: receipt[i].transaction_hash = tx_hash[i]
/// ```
/// 
/// ### Proof Depth Bounds
/// All proof vectors must satisfy: `len(proof) ≤ 64` (maximum Merkle tree depth)
/// 
/// ### Size Complexity
/// - Serialized size: O(Σ(proof_lengths)) where proof_lengths = lengths of all proof vectors
/// - Memory footprint: 32 * 3 + 20 * 3 + O(total_proof_bytes) = 156 + O(proofs)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdjustmentData {
    /// Post-execution state root (32 bytes)
    /// Must equal merkle_root(state_trie) after block execution
    pub state_root: B256,
    
    /// Transaction trie root (32 bytes)
    /// Must equal merkle_root(block.transactions)
    pub transactions_root: B256,
    
    /// Receipt trie root (32 bytes) 
    /// Must equal merkle_root(execution_receipts)
    pub receipts_root: B256,
    
    /// Block builder's Ethereum address (20 bytes)
    /// Must be verifiable against builder_proof
    pub builder_address: Address,
    
    /// Merkle proof for builder_address inclusion in state_root
    /// Proof depth bounded by: len(builder_proof) ≤ 64
    pub builder_proof: Vec<Vec<u8>>,
    
    /// Fee recipient address (20 bytes)
    /// Address receiving block rewards and tips
    pub fee_recipient_address: Address,
    
    /// Merkle proof for fee_recipient_address
    /// Validates fee recipient against state commitment
    pub fee_recipient_proof: Vec<Vec<u8>>,
    
    /// Fee payer address (20 bytes)
    /// Address paying for transaction inclusion fees
    pub fee_payer_address: Address,
    
    /// Merkle proof for fee_payer_address
    /// Validates fee payer against state commitment  
    pub fee_payer_proof: Vec<Vec<u8>>,
    
    /// Merkle proof for placeholder transaction
    /// Used for adjustable transaction replacement validation
    pub placeholder_tx_proof: Vec<Vec<u8>>,
    
    /// Merkle proof for placeholder receipt
    /// Used for adjustable receipt replacement validation
    pub placeholder_receipt_proof: Vec<Vec<u8>>,
}

impl Default for AdjustmentData {
    fn default() -> Self {
        Self {
            state_root: B256::default(),
            transactions_root: B256::default(),
            receipts_root: B256::default(),
            builder_address: Address::default(),
            builder_proof: Vec::new(),
            fee_recipient_address: Address::default(),
            fee_recipient_proof: Vec::new(),
            fee_payer_address: Address::default(),
            fee_payer_proof: Vec::new(),
            placeholder_tx_proof: Vec::new(),
            placeholder_receipt_proof: Vec::new(),
        }
    }
}

impl AdjustmentData {
    /// Validate all mathematical invariants for this adjustment data
    pub fn validate_invariants(&self) -> Result<(), InvariantViolation> {
        let proofs = [
            &self.builder_proof,
            &self.fee_recipient_proof,
            &self.fee_payer_proof,
            &self.placeholder_tx_proof,
            &self.placeholder_receipt_proof,
        ];
        
        // Validate all proof structures
        for proof in &proofs {
            InvariantValidator::validate_proof_structure(proof)?;
        }
        
        // Validate addresses (builder_address must be non-zero)
        let addresses = [
            (self.builder_address, "builder_address", false),
            (self.fee_recipient_address, "fee_recipient_address", true),
            (self.fee_payer_address, "fee_payer_address", true),
        ];
        
        for &(address, field_name, allow_zero) in &addresses {
            ValidatedAddress::new(address, field_name.to_string(), allow_zero)?;
        }
        
        // State root should not be zero in production usage
        if self.state_root == B256::ZERO {
            return Err(InvariantViolation::HashConsistencyFailed {
                field: "state_root".to_string(),
            });
        }
        
        Ok(())
    }
    
    /// Create type-safe bounded proofs from this adjustment data
    pub fn as_bounded_proofs(&self) -> Result<
        (
            BoundedProof<MAX_PROOF_DEPTH>,
            BoundedProof<MAX_PROOF_DEPTH>,
            BoundedProof<MAX_PROOF_DEPTH>,
            BoundedProof<MAX_PROOF_DEPTH>,
            BoundedProof<MAX_PROOF_DEPTH>,
        ),
        InvariantViolation,
    > {
        Ok((
            BoundedProof::new(self.builder_proof.clone())?,
            BoundedProof::new(self.fee_recipient_proof.clone())?,
            BoundedProof::new(self.fee_payer_proof.clone())?,
            BoundedProof::new(self.placeholder_tx_proof.clone())?,
            BoundedProof::new(self.placeholder_receipt_proof.clone())?,
        ))
    }
    
    /// Get type-safe state root wrapper
    pub fn state_root_validated(&self) -> Result<StateRoot, InvariantViolation> {
        StateRoot::new(self.state_root)
    }
    
    /// Get type-safe transaction root wrapper
    pub fn transactions_root_validated(&self) -> TransactionRoot {
        TransactionRoot::new(self.transactions_root)
    }
    
    /// Get type-safe receipt root wrapper
    pub fn receipts_root_validated(&self) -> ReceiptRoot {
        ReceiptRoot::new(self.receipts_root)
    }
    
    /// Calculate total proof overhead in bytes
    pub fn proof_overhead_bytes(&self) -> usize {
        [
            &self.builder_proof,
            &self.fee_recipient_proof,
            &self.fee_payer_proof,
            &self.placeholder_tx_proof,
            &self.placeholder_receipt_proof,
        ]
        .iter()
        .map(|proof| proof.iter().map(|element| element.len()).sum::<usize>())
        .sum()
    }
    
    /// Get maximum proof depth across all proofs
    pub fn max_proof_depth(&self) -> usize {
        [
            self.builder_proof.len(),
            self.fee_recipient_proof.len(),
            self.fee_payer_proof.len(),
            self.placeholder_tx_proof.len(),
            self.placeholder_receipt_proof.len(),
        ]
        .into_iter()
        .max()
        .unwrap_or(0)
    }
}
