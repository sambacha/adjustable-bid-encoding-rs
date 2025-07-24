//! Property-based testing with proptest for adjustable bid encoding.
//!
//! This module provides comprehensive property tests using proptest to validate
//! mathematical invariants and ensure correctness across all possible inputs.

use crate::invariants::*;
use crate::types::*;
use alloy_primitives::{Address, B256, U256};
use alloy_rpc_types_beacon::relay::BidTrace;
use arbitrary::{Arbitrary, Unstructured};
use proptest::prelude::*;

/// Custom strategy for generating valid B256 hashes
pub fn b256_strategy() -> impl Strategy<Value = B256> {
    prop::array::uniform32(any::<u8>()).prop_map(B256::from)
}

/// Strategy for generating non-zero B256 hashes (for state roots)
pub fn non_zero_b256_strategy() -> impl Strategy<Value = B256> {
    b256_strategy().prop_filter("must be non-zero", |h| *h != B256::ZERO)
}

/// Custom strategy for generating valid Ethereum addresses
pub fn address_strategy() -> impl Strategy<Value = Address> {
    prop::array::uniform20(any::<u8>()).prop_map(Address::from)
}

/// Strategy for generating non-zero addresses
pub fn non_zero_address_strategy() -> impl Strategy<Value = Address> {
    address_strategy().prop_filter("must be non-zero", |a| *a != Address::ZERO)
}

/// Strategy for generating bounded Merkle proofs
pub fn bounded_proof_strategy(max_depth: usize) -> impl Strategy<Value = Vec<Vec<u8>>> {
    prop::collection::vec(
        prop::array::uniform32(any::<u8>()).prop_map(|arr| arr.to_vec()),
        0..=max_depth,
    )
}

/// Strategy for generating valid BLS signatures (96 bytes)
pub fn bls_signature_strategy() -> impl Strategy<Value = [u8; 96]> {
    // proptest doesn't have uniform96, so we use a different approach
    (0..96).map(|_| any::<u8>()).collect::<Vec<_>>().prop_map(|v| {
        let mut arr = [0u8; 96];
        arr.copy_from_slice(&v);
        arr
    })
}

/// Strategy for generating valid gas limits
pub fn gas_limit_strategy() -> impl Strategy<Value = u64> {
    1u64..=MAX_GAS_LIMIT
}

/// Strategy for generating gas usage that respects the limit
pub fn gas_usage_strategy(limit: u64) -> impl Strategy<Value = u64> {
    0u64..=limit
}

/// Strategy for generating valid bid values (in wei)
pub fn bid_value_strategy() -> impl Strategy<Value = U256> {
    // Generate values from 0.001 ETH to 10 ETH (within u64 range)
    (1_000_000_000_000_000u64..=10_000_000_000_000_000_000u64)
        .prop_map(U256::from)
}

/// Strategy for generating valid slot numbers
pub fn slot_strategy() -> impl Strategy<Value = u64> {
    // Ethereum mainnet started at slot 0, reasonable range for testing
    0u64..=10_000_000u64
}

/// Strategy for generating valid BLS public keys (48 bytes)  
pub fn bls_pubkey_strategy() -> impl Strategy<Value = [u8; 48]> {
    // proptest doesn't have uniform48, so we use a different approach
    (0..48).map(|_| any::<u8>()).collect::<Vec<_>>().prop_map(|v| {
        let mut arr = [0u8; 48];
        arr.copy_from_slice(&v);
        arr
    })
}

/// Generate a valid AdjustmentData with all invariants satisfied
pub fn adjustment_data_strategy() -> impl Strategy<Value = AdjustmentData> {
    (
        non_zero_b256_strategy(), // state_root
        b256_strategy(),          // transactions_root
        b256_strategy(),          // receipts_root
        non_zero_address_strategy(), // builder_address
        bounded_proof_strategy(MAX_PROOF_DEPTH), // builder_proof
        address_strategy(),       // fee_recipient_address
        bounded_proof_strategy(MAX_PROOF_DEPTH), // fee_recipient_proof
        address_strategy(),       // fee_payer_address
        bounded_proof_strategy(MAX_PROOF_DEPTH), // fee_payer_proof
        bounded_proof_strategy(MAX_PROOF_DEPTH), // placeholder_tx_proof
        bounded_proof_strategy(MAX_PROOF_DEPTH), // placeholder_receipt_proof
    ).prop_map(|(state_root, tx_root, receipt_root, builder_addr, builder_proof,
                 fee_recipient, fee_recipient_proof, fee_payer, fee_payer_proof,
                 placeholder_tx_proof, placeholder_receipt_proof)| {
        AdjustmentData {
            state_root,
            transactions_root: tx_root,
            receipts_root: receipt_root,
            builder_address: builder_addr,
            builder_proof,
            fee_recipient_address: fee_recipient,
            fee_recipient_proof,
            fee_payer_address: fee_payer,
            fee_payer_proof,
            placeholder_tx_proof,
            placeholder_receipt_proof,
        }
    })
}

/// Generate a valid BidTrace
pub fn bid_trace_strategy() -> impl Strategy<Value = BidTrace> {
    (
        slot_strategy(),
        b256_strategy(), // parent_hash
        b256_strategy(), // block_hash
        bls_pubkey_strategy(), // builder_pubkey
        bls_pubkey_strategy(), // proposer_pubkey
        address_strategy(), // proposer_fee_recipient
        gas_limit_strategy(),
        bid_value_strategy(),
    ).prop_flat_map(|(slot, parent_hash, block_hash, builder_pubkey, proposer_pubkey,
                      proposer_fee_recipient, gas_limit, value)| {
        gas_usage_strategy(gas_limit).prop_map(move |gas_used| BidTrace {
            slot,
            parent_hash,
            block_hash,
            builder_pubkey: alloy_primitives::FixedBytes::from(builder_pubkey),
            proposer_pubkey: alloy_primitives::FixedBytes::from(proposer_pubkey),
            proposer_fee_recipient,
            gas_limit,
            gas_used,
            value,
        })
    })
}

/// Generate a valid AdjustableSubmitBlockRequest (Deneb)
pub fn adjustable_submit_block_request_strategy() -> impl Strategy<Value = AdjustableSubmitBlockRequest> {
    (
        bid_trace_strategy(),
        prop::collection::vec(any::<u8>(), 0..=4096), // execution_payload
        bls_signature_strategy(),
        adjustment_data_strategy(),
    ).prop_map(|(message, payload_bytes, signature, adjustment_data)| {
        AdjustableSubmitBlockRequest {
            message,
            execution_payload: bytes::Bytes::from(payload_bytes),
            blobs_bundle: Default::default(), // Use default for simplicity
            signature,
            adjustment_data,
        }
    })
}

/// Generate a valid AdjustableSubmitBlockRequestV4 (Electra)
pub fn adjustable_submit_block_request_v4_strategy() -> impl Strategy<Value = AdjustableSubmitBlockRequestV4> {
    (
        bid_trace_strategy(),
        prop::collection::vec(any::<u8>(), 0..=4096), // execution_payload
        prop::collection::vec(any::<u8>(), 0..=1024), // execution_requests
        bls_signature_strategy(),
        adjustment_data_strategy(),
    ).prop_map(|(message, payload_bytes, requests_bytes, signature, adjustment_data)| {
        AdjustableSubmitBlockRequestV4 {
            message,
            execution_payload: bytes::Bytes::from(payload_bytes),
            blobs_bundle: Default::default(), // Use default for simplicity
            execution_requests: bytes::Bytes::from(requests_bytes),
            signature,
            adjustment_data,
        }
    })
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use crate::invariants::InvariantValidator;

    proptest! {
        /// Test that all generated adjustment data satisfies invariants
        #[test]
        fn prop_adjustment_data_satisfies_invariants(adjustment_data in adjustment_data_strategy()) {
            // Check proof depth invariants
            prop_assert!(adjustment_data.builder_proof.len() <= MAX_PROOF_DEPTH);
            prop_assert!(adjustment_data.fee_recipient_proof.len() <= MAX_PROOF_DEPTH);
            prop_assert!(adjustment_data.fee_payer_proof.len() <= MAX_PROOF_DEPTH);
            prop_assert!(adjustment_data.placeholder_tx_proof.len() <= MAX_PROOF_DEPTH);
            prop_assert!(adjustment_data.placeholder_receipt_proof.len() <= MAX_PROOF_DEPTH);

            // Check state root is non-zero
            prop_assert_ne!(adjustment_data.state_root, B256::ZERO);

            // Check builder address is non-zero
            prop_assert_ne!(adjustment_data.builder_address, Address::ZERO);

            // Validate all proofs have correct structure
            let proofs = [
                &adjustment_data.builder_proof,
                &adjustment_data.fee_recipient_proof,
                &adjustment_data.fee_payer_proof,
                &adjustment_data.placeholder_tx_proof,
                &adjustment_data.placeholder_receipt_proof,
            ];

            for proof in &proofs {
                prop_assert!(InvariantValidator::validate_proof_structure(proof).is_ok());
            }
        }

        /// Test that all generated bid traces have valid gas parameters
        #[test]
        fn prop_bid_trace_gas_invariants(bid_trace in bid_trace_strategy()) {
            // Gas used should not exceed gas limit
            prop_assert!(bid_trace.gas_used <= bid_trace.gas_limit);
            
            // Gas limit should not exceed maximum
            prop_assert!(bid_trace.gas_limit <= MAX_GAS_LIMIT);
            
            // Validate gas parameters
            prop_assert!(InvariantValidator::validate_gas_parameters(
                bid_trace.gas_limit, 
                bid_trace.gas_used
            ).is_ok());
        }

        /// Test that all generated signatures have correct length
        #[test]
        fn prop_signature_length_invariant(request in adjustable_submit_block_request_strategy()) {
            prop_assert_eq!(request.signature.len(), BLS_SIGNATURE_LENGTH);
            prop_assert!(InvariantValidator::validate_signature_structure(&request.signature).is_ok());
        }

        /// Test comprehensive invariant validation for Deneb requests
        #[test]
        fn prop_deneb_request_comprehensive_validation(request in adjustable_submit_block_request_strategy()) {
            let proofs = [
                request.adjustment_data.builder_proof.as_slice(),
                request.adjustment_data.fee_recipient_proof.as_slice(),
                request.adjustment_data.fee_payer_proof.as_slice(),
                request.adjustment_data.placeholder_tx_proof.as_slice(),
                request.adjustment_data.placeholder_receipt_proof.as_slice(),
            ];

            let addresses = [
                (request.adjustment_data.builder_address, "builder_address", false),
                (request.adjustment_data.fee_recipient_address, "fee_recipient_address", true),
                (request.adjustment_data.fee_payer_address, "fee_payer_address", true),
            ];

            prop_assert!(InvariantValidator::validate_all_invariants(
                &proofs,
                &request.signature,
                request.message.gas_limit,
                request.message.gas_used,
                &addresses,
            ).is_ok());
        }

        /// Test comprehensive invariant validation for Electra requests
        #[test]
        fn prop_electra_request_comprehensive_validation(request in adjustable_submit_block_request_v4_strategy()) {
            let proofs = [
                request.adjustment_data.builder_proof.as_slice(),
                request.adjustment_data.fee_recipient_proof.as_slice(),
                request.adjustment_data.fee_payer_proof.as_slice(),
                request.adjustment_data.placeholder_tx_proof.as_slice(),
                request.adjustment_data.placeholder_receipt_proof.as_slice(),
            ];

            let addresses = [
                (request.adjustment_data.builder_address, "builder_address", false),
                (request.adjustment_data.fee_recipient_address, "fee_recipient_address", true),
                (request.adjustment_data.fee_payer_address, "fee_payer_address", true),
            ];

            prop_assert!(InvariantValidator::validate_all_invariants(
                &proofs,
                &request.signature,
                request.message.gas_limit,
                request.message.gas_used,
                &addresses,
            ).is_ok());
        }

        /// Test that type-safe invariant wrappers work correctly
        #[test]
        fn prop_type_safe_invariants(
            proof_vec in bounded_proof_strategy(MAX_PROOF_DEPTH),
            signature in bls_signature_strategy(),
            state_hash in non_zero_b256_strategy(),
            gas_limit in gas_limit_strategy(),
            gas_usage in 0u64..MAX_GAS_LIMIT,
        ) {
            // BoundedProof should always succeed within limits
            let bounded_proof = BoundedProof::<MAX_PROOF_DEPTH>::new(proof_vec);
            prop_assert!(bounded_proof.is_ok());

            // ValidatedSignature should always succeed with correct length
            let validated_sig = ValidatedSignature::new(signature);
            prop_assert_eq!(validated_sig.as_bytes(), &signature);

            // StateRoot should succeed with non-zero hash
            let state_root = StateRoot::new(state_hash);
            prop_assert!(state_root.is_ok());

            // Gas validation should work correctly
            let validated_limit = ValidatedGasLimit::new(gas_limit);
            prop_assert!(validated_limit.is_ok());
            
            if let Ok(limit) = validated_limit {
                let usage_result = limit.validate_usage(gas_usage);
                if gas_usage <= gas_limit {
                    prop_assert!(usage_result.is_ok());
                } else {
                    prop_assert!(usage_result.is_err());
                }
            }
        }

        /// Test serialization roundtrip properties (when SSZ is enabled)
        #[cfg(feature = "ssz")]
        #[test]
        fn prop_ssz_roundtrip_adjustment_data(adjustment_data in adjustment_data_strategy()) {
            use sszb::{SszEncode, SszDecode};
            
            let encoded = adjustment_data.to_ssz();
            let decoded = AdjustmentData::from_ssz_bytes(&encoded);
            
            prop_assert!(decoded.is_ok());
            prop_assert_eq!(decoded.unwrap(), adjustment_data);
        }

        /// Test serialization roundtrip for Deneb requests (disabled - needs custom SSZ impl)
        // #[cfg(feature = "ssz")]
        // #[test]
        // fn prop_ssz_roundtrip_deneb_request(request in adjustable_submit_block_request_strategy()) {
        //     use sszb::{SszEncode, SszDecode};
        //     
        //     let encoded = request.to_ssz();
        //     let decoded = AdjustableSubmitBlockRequest::from_ssz_bytes(&encoded);
        //     
        //     prop_assert!(decoded.is_ok());
        //     prop_assert_eq!(decoded.unwrap(), request);
        // }

        /// Test serialization roundtrip for Electra requests (disabled - needs custom SSZ impl)
        // #[cfg(feature = "ssz")]
        // #[test]
        // fn prop_ssz_roundtrip_electra_request(request in adjustable_submit_block_request_v4_strategy()) {
        //     use sszb::{SszEncode, SszDecode};
        //     
        //     let encoded = request.to_ssz();
        //     let decoded = AdjustableSubmitBlockRequestV4::from_ssz_bytes(&encoded);
        //     
        //     prop_assert!(decoded.is_ok());
        //     prop_assert_eq!(decoded.unwrap(), request);
        // }

        /// Test that hash consistency is maintained across operations
        #[test]
        fn prop_hash_consistency(
            state_hash in non_zero_b256_strategy(),
            tx_hash in b256_strategy(),
            receipt_hash in b256_strategy(),
        ) {
            let state_root = StateRoot::new(state_hash).unwrap();
            let tx_root = TransactionRoot::new(tx_hash);
            let receipt_root = ReceiptRoot::new(receipt_hash);

            // Verify that wrapped values maintain their original hash
            prop_assert_eq!(state_root.hash(), state_hash);
            prop_assert_eq!(tx_root.hash(), tx_hash);
            prop_assert_eq!(receipt_root.hash(), receipt_hash);

            // Verify conversion back to original type
            prop_assert_eq!(state_root.into_hash(), state_hash);
            prop_assert_eq!(tx_root.into_hash(), tx_hash);
            prop_assert_eq!(receipt_root.into_hash(), receipt_hash);
        }
    }
}

/// Implement Arbitrary for custom property testing
impl<'a> Arbitrary<'a> for AdjustmentData {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(AdjustmentData {
            state_root: B256::from(u.arbitrary::<[u8; 32]>()?),
            transactions_root: B256::from(u.arbitrary::<[u8; 32]>()?),
            receipts_root: B256::from(u.arbitrary::<[u8; 32]>()?),
            builder_address: Address::from(u.arbitrary::<[u8; 20]>()?),
            builder_proof: {
                let len = u.int_in_range(0..=MAX_PROOF_DEPTH)?;
                (0..len).map(|_| {
                    Ok(u.arbitrary::<[u8; 32]>()?.to_vec())
                }).collect::<arbitrary::Result<Vec<_>>>()?
            },
            fee_recipient_address: Address::from(u.arbitrary::<[u8; 20]>()?),
            fee_recipient_proof: {
                let len = u.int_in_range(0..=MAX_PROOF_DEPTH)?;
                (0..len).map(|_| {
                    Ok(u.arbitrary::<[u8; 32]>()?.to_vec())
                }).collect::<arbitrary::Result<Vec<_>>>()?
            },
            fee_payer_address: Address::from(u.arbitrary::<[u8; 20]>()?),
            fee_payer_proof: {
                let len = u.int_in_range(0..=MAX_PROOF_DEPTH)?;
                (0..len).map(|_| {
                    Ok(u.arbitrary::<[u8; 32]>()?.to_vec())
                }).collect::<arbitrary::Result<Vec<_>>>()?
            },
            placeholder_tx_proof: {
                let len = u.int_in_range(0..=MAX_PROOF_DEPTH)?;
                (0..len).map(|_| {
                    Ok(u.arbitrary::<[u8; 32]>()?.to_vec())
                }).collect::<arbitrary::Result<Vec<_>>>()?
            },
            placeholder_receipt_proof: {
                let len = u.int_in_range(0..=MAX_PROOF_DEPTH)?;
                (0..len).map(|_| {
                    Ok(u.arbitrary::<[u8; 32]>()?.to_vec())
                }).collect::<arbitrary::Result<Vec<_>>>()?
            },
        })
    }
}