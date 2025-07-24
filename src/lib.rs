//! # Adjustable Bid Encoding for Rust
//!
//! This crate provides Rust implementations of adjustable block submission requests
//! for Ethereum block builders, compatible with the Go reference implementation.
//!
//! ## Features
//!
//! - **Deneb Support**: `AdjustableSubmitBlockRequest` for Deneb fork
//! - **Electra Support**: `AdjustableSubmitBlockRequestV4` for Electra fork  
//! - **SSZ Serialization**: Optional SSZ encoding/decoding with `sszb` (when enabled)
//! - **Alloy Integration**: Uses latest alloy-rs ecosystem for Ethereum types
//!
//! ## Mathematical Foundations
//! 
//! The adjustable bid encoding relies on several cryptographic and mathematical properties:
//! 
//! ### Merkle Tree Proofs
//! Each submission includes Merkle proofs that must satisfy:
//! ```text
//! verify_merkle_proof(proof, leaf, root) = true
//! root = H(H(...H(H(leaf, sibling[0]), sibling[1])...), sibling[n])
//! ```
//! Where `H` is the Keccak-256 hash function.
//! 
//! ### BLS Signature Verification
//! Block submissions require BLS signatures over the bid trace:
//! ```text
//! verify_bls_signature(signature, message_hash, builder_pubkey) = true
//! message_hash = hash_tree_root(BidTrace)
//! ```
//! 
//! ### Size Complexity
//! - Proof verification: O(log n) where n is the tree size
//! - Serialization: O(m) where m is the total data size
//! - Maximum proof depth: 64 levels (protocol limit)
//!
//! ## Usage
//!
//! ```rust
//! use adjustable_bid_encoding_rs::types::{AdjustableSubmitBlockRequest, AdjustmentData};
//! use alloy_primitives::{Address, B256};
//!
//! // Create adjustment data with cryptographic proofs
//! let adjustment_data = AdjustmentData {
//!     state_root: B256::from([0x12; 32]),        // Post-execution state root
//!     transactions_root: B256::from([0x34; 32]), // Transaction trie root
//!     receipts_root: B256::from([0x56; 32]),     // Receipt trie root
//!     builder_address: Address::from([0x78; 20]),
//!     builder_proof: vec![                       // Merkle proof for builder
//!         vec![0xab; 32], // Sibling hash at level 0
//!         vec![0xcd; 32], // Sibling hash at level 1
//!     ],
//!     fee_recipient_address: Address::from([0x9a; 20]),
//!     fee_recipient_proof: vec![vec![0xef; 32]],
//!     fee_payer_address: Address::from([0xbc; 20]),
//!     fee_payer_proof: vec![],
//!     placeholder_tx_proof: vec![],
//!     placeholder_receipt_proof: vec![],
//! };
//!
//! // Create request with mathematical invariant validation
//! let request = AdjustableSubmitBlockRequest {
//!     message: Default::default(),
//!     execution_payload: Default::default(),
//!     blobs_bundle: Default::default(),
//!     signature: [0; 96], // BLS signature (96 bytes for BLS12-381)
//!     adjustment_data,
//! };
//! 
//! // Verify invariants before submission
//! assert_eq!(request.signature.len(), 96);  // BLS signature size
//! assert!(request.adjustment_data.builder_proof.len() <= 64);  // Max proof depth
//! ```
//!
//! ## Examples
//! 
//! See the `examples/` directory for comprehensive usage examples:
//! - `mev_boost_integration.rs`: Complete MEV-Boost relay integration
//! - `proof_verification.rs`: Merkle proof generation and verification
//! - `roundtrip.rs`: SSZ serialization roundtrip testing
//!
//! ## SSZ Feature
//!
//! Enable SSZ serialization by adding the `ssz` feature:
//!
//! ```toml
//! [dependencies]
//! adjustable-bid-encoding-rs = { version = "0.1", features = ["ssz"] }
//! ```
//! 
//! With SSZ enabled, all types implement `SszEncode` and `SszDecode` for efficient
//! binary serialization compatible with Ethereum's consensus layer.

pub mod types;
pub mod invariants;

#[cfg(any(test, feature = "testing"))]
pub mod property_tests;

#[cfg(test)]
mod tests {
    use super::types::*;
    use alloy_primitives::{Address, B256};

    #[test]
    fn test_adjustment_data_creation() {
        let adjustment_data = AdjustmentData {
            state_root: B256::from([1; 32]),
            transactions_root: B256::from([2; 32]),
            receipts_root: B256::from([3; 32]),
            builder_address: Address::from([4; 20]),
            builder_proof: vec![vec![1, 2, 3], vec![4, 5, 6]],
            fee_recipient_address: Address::from([5; 20]),
            fee_recipient_proof: vec![],
            fee_payer_address: Address::from([6; 20]),
            fee_payer_proof: vec![],
            placeholder_tx_proof: vec![],
            placeholder_receipt_proof: vec![],
        };

        assert_eq!(adjustment_data.state_root, B256::from([1; 32]));
        assert_eq!(adjustment_data.builder_proof.len(), 2);
    }

    #[test]
    fn test_deneb_request_creation() {
        let request = AdjustableSubmitBlockRequest::default();
        assert_eq!(request.signature.len(), 96);
    }

    #[test]
    fn test_electra_request_creation() {
        let request = AdjustableSubmitBlockRequestV4::default();
        assert_eq!(request.signature.len(), 96);
    }
}
