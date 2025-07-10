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
//! ## Usage
//!
//! ```rust
//! use adjustable_bid_encoding_rs::types::{AdjustableSubmitBlockRequest, AdjustmentData};
//! use alloy_primitives::{Address, B256};
//!
//! // Create adjustment data
//! let adjustment_data = AdjustmentData {
//!     state_root: B256::default(),
//!     transactions_root: B256::default(),
//!     receipts_root: B256::default(),
//!     builder_address: Address::default(),
//!     builder_proof: vec![],
//!     fee_recipient_address: Address::default(),
//!     fee_recipient_proof: vec![],
//!     fee_payer_address: Address::default(),
//!     fee_payer_proof: vec![],
//!     placeholder_tx_proof: vec![],
//!     placeholder_receipt_proof: vec![],
//! };
//!
//! // Create request
//! let request = AdjustableSubmitBlockRequest {
//!     message: Default::default(),
//!     execution_payload: Default::default(),
//!     blobs_bundle: Default::default(),
//!     signature: [0; 96],
//!     adjustment_data,
//! };
//! ```
//!
//! ## SSZ Feature
//!
//! Enable SSZ serialization by adding the `ssz` feature:
//!
//! ```toml
//! [dependencies]
//! adjustable-bid-encoding-rs = { version = "0.1", features = ["ssz"] }
//! ```

pub mod types;

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
