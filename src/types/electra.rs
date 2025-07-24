use crate::types::adjustment_data::AdjustmentData;
use alloy_eips::eip4844::BlobTransactionSidecar;
use alloy_rpc_types_beacon::relay::BidTrace;
use bytes::Bytes;
// Note: SSZ support requires manual implementation due to external types
// that don't have built-in SSZ support (BidTrace, Bytes, BlobTransactionSidecar)

/// Electra fork adjustable block submission request (V4).
/// 
/// This structure extends the Deneb format with execution requests support,
/// enabling validator consolidations, withdrawals, and other EIP-7685 operations.
/// 
/// ## Mathematical Invariants
/// 
/// ### All Deneb Invariants Plus:
/// 
/// ### Execution Requests Consistency
/// ```text
/// execution_requests_root = merkle_root(execution_requests)
/// execution_payload.requests_root = execution_requests_root
/// ```
/// 
/// ### Consolidation Request Validation
/// ```text
/// ∀ consolidation ∈ execution_requests.consolidations:
///   verify_consolidation_signature(consolidation) = true
///   consolidation.source_index ≠ consolidation.target_index
/// ```
/// 
/// ### Withdrawal Request Validation  
/// ```text
/// ∀ withdrawal ∈ execution_requests.withdrawals:
///   withdrawal.amount ≤ validator_balance[withdrawal.validator_index]
///   verify_withdrawal_credentials(withdrawal) = true
/// ```
/// 
/// ### Size Bounds (Electra Extensions)
/// - Execution requests: O(|consolidations| + |withdrawals| + |deposits|)
/// - Maximum consolidations per block: 1 (EIP-7251 limit)
/// - Maximum withdrawal requests per block: 16 (EIP-7002 limit)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdjustableSubmitBlockRequestV4 {
    /// Bid trace containing block metadata and builder information
    /// Must be signed by the builder's BLS key
    pub message: BidTrace,
    
    /// Serialized execution payload with Electra enhancements
    /// Includes EIP-7685 execution requests root
    pub execution_payload: Bytes,
    
    /// EIP-4844 blob transaction sidecar
    /// Contains blobs, commitments, and KZG proofs for data availability
    pub blobs_bundle: BlobTransactionSidecar,
    
    /// EIP-7685 execution requests (consolidations, withdrawals, deposits)
    /// Serialized list of execution layer requests for consensus layer processing
    pub execution_requests: Bytes,
    
    /// BLS signature over message hash (96 bytes)
    /// Cryptographic proof of builder authorization
    pub signature: [u8; 96],
    
    /// Adjustment data with Merkle proofs
    /// Enables post-submission parameter adjustments with cryptographic verification
    pub adjustment_data: AdjustmentData,
}

impl Default for AdjustableSubmitBlockRequestV4 {
    fn default() -> Self {
        Self {
            message: Default::default(),
            execution_payload: Bytes::new(),
            blobs_bundle: Default::default(),
            execution_requests: Bytes::new(),
            signature: [0; 96],
            adjustment_data: Default::default(),
        }
    }
}
