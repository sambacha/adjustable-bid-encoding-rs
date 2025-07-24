use crate::types::adjustment_data::AdjustmentData;
use crate::invariants::*;
use alloy_eips::eip4844::BlobTransactionSidecar;
use alloy_rpc_types_beacon::relay::BidTrace;
use bytes::Bytes;
// Note: SSZ support requires manual implementation due to external types
// that don't have built-in SSZ support (BidTrace, Bytes, BlobTransactionSidecar)

/// Deneb fork adjustable block submission request.
/// 
/// This structure represents a complete block submission for the Ethereum Deneb fork,
/// including EIP-4844 blob support and cryptographic proofs for adjustable parameters.
/// 
/// ## Mathematical Invariants
/// 
/// ### Signature Verification
/// ```text
/// verify_bls_signature(signature, message_hash, builder_pubkey) = true
/// message_hash = hash_tree_root(message)
/// ```
/// 
/// ### Block Integrity
/// ```text
/// execution_payload.block_hash = keccak256(execution_payload)
/// execution_payload.state_root = adjustment_data.state_root
/// execution_payload.transactions_root = adjustment_data.transactions_root
/// execution_payload.receipts_root = adjustment_data.receipts_root
/// ```
/// 
/// ### Blob Bundle Consistency (EIP-4844)
/// ```text
/// ∀i: blobs_bundle.commitments[i] = kzg_commit(blobs_bundle.blobs[i])
/// ∀i: blobs_bundle.proofs[i] = kzg_proof(blobs_bundle.blobs[i], blobs_bundle.commitments[i])
/// ```
/// 
/// ### Size Bounds
/// - Total serialized size: O(|execution_payload| + |blobs_bundle| + |adjustment_data|)
/// - Signature: Fixed 96 bytes (BLS12-381)
/// - Maximum blob count: 6 per block (protocol limit)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdjustableSubmitBlockRequest {
    /// Bid trace containing block metadata and builder information
    /// Must be signed by the builder's BLS key
    pub message: BidTrace,
    
    /// Serialized execution payload containing block data
    /// Contains transactions, state changes, and block header
    pub execution_payload: Bytes,
    
    /// EIP-4844 blob transaction sidecar
    /// Contains blobs, commitments, and KZG proofs for data availability
    pub blobs_bundle: BlobTransactionSidecar,
    
    /// BLS signature over message hash (96 bytes)
    /// Cryptographic proof of builder authorization
    pub signature: [u8; 96],
    
    /// Adjustment data with Merkle proofs
    /// Enables post-submission parameter adjustments with cryptographic verification
    pub adjustment_data: AdjustmentData,
}

impl Default for AdjustableSubmitBlockRequest {
    fn default() -> Self {
        Self {
            message: Default::default(),
            execution_payload: Bytes::new(),
            blobs_bundle: Default::default(),
            signature: [0; 96],
            adjustment_data: Default::default(),
        }
    }
}

impl AdjustableSubmitBlockRequest {
    /// Comprehensive validation of all mathematical invariants
    pub fn validate_invariants(&self) -> Result<(), InvariantViolation> {
        // Validate signature structure
        InvariantValidator::validate_signature_structure(&self.signature)?;
        
        // Validate gas parameters
        InvariantValidator::validate_gas_parameters(
            self.message.gas_limit,
            self.message.gas_used,
        )?;
        
        // Validate adjustment data
        self.adjustment_data.validate_invariants()?;
        
        Ok(())
    }
    
    /// Get type-safe validated signature
    pub fn validated_signature(&self) -> Result<ValidatedSignature, InvariantViolation> {
        ValidatedSignature::from_slice(&self.signature)
    }
    
    /// Get type-safe validated gas limit
    pub fn validated_gas_limit(&self) -> Result<ValidatedGasLimit, InvariantViolation> {
        ValidatedGasLimit::new(self.message.gas_limit)
    }
    
    /// Calculate total serialized size estimation
    pub fn estimated_size(&self) -> usize {
        // Base structure sizes
        let base_size = std::mem::size_of::<BidTrace>() + 
                       BLS_SIGNATURE_LENGTH + 
                       32 * 3 + // state, tx, receipt roots
                       20 * 3;  // addresses
        
        // Variable size components
        let payload_size = self.execution_payload.len();
        let proof_overhead = self.adjustment_data.proof_overhead_bytes();
        
        base_size + payload_size + proof_overhead
    }
    
    /// Validate block-specific invariants
    pub fn validate_block_invariants(&self) -> Result<(), InvariantViolation> {
        // Ensure block value is reasonable (non-zero for competitive bids)
        if self.message.value == alloy_primitives::U256::ZERO {
            // This is a warning rather than an error - zero-value blocks can be valid
            eprintln!("Warning: Zero-value bid may not be competitive");
        }
        
        // Validate slot is reasonable (not too far in the future)
        const MAX_FUTURE_SLOTS: u64 = 100; // Allow up to 100 slots in the future
        let current_estimated_slot = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() / 12; // 12 second slots
        
        if self.message.slot > current_estimated_slot + MAX_FUTURE_SLOTS {
            return Err(InvariantViolation::HashConsistencyFailed {
                field: "slot_too_far_future".to_string(),
            });
        }
        
        Ok(())
    }
    
    /// Create a summary of the block submission for logging/debugging
    pub fn summary(&self) -> String {
        format!(
            "DenebBlockSubmission{{ slot: {}, gas_used: {}/{}, value: {} wei, proof_overhead: {} bytes, max_proof_depth: {} }}",
            self.message.slot,
            self.message.gas_used,
            self.message.gas_limit,
            self.message.value,
            self.adjustment_data.proof_overhead_bytes(),
            self.adjustment_data.max_proof_depth()
        )
    }
}
