#![no_main]

use libfuzzer_sys::fuzz_target;
use adjustable_bid_encoding_rs::types::AdjustableSubmitBlockRequest;
use adjustable_bid_encoding_rs::invariants::{InvariantValidator, BLS_SIGNATURE_LENGTH};
use arbitrary::Arbitrary;

#[cfg(feature = "ssz")]
use sszb::{SszEncode, SszDecode};

/// Fuzz target for AdjustableSubmitBlockRequest (Deneb) SSZ operations
/// 
/// This fuzzer tests:
/// 1. SSZ serialization/deserialization of complete block requests
/// 2. Invariant validation across all components
/// 3. Gas parameter validation
/// 4. Signature structure validation
/// 5. Memory safety with large payloads
fuzz_target!(|data: &[u8]| {
    // Try to create a block request from arbitrary bytes
    if let Ok(mut unstructured) = arbitrary::Unstructured::new(data) {
        // Generate execution payload size (limited to prevent OOM)
        if let Ok(payload_size) = unstructured.int_in_range(0..=8192) {
            if let Ok(payload_bytes) = (0..payload_size)
                .map(|_| unstructured.arbitrary::<u8>())
                .collect::<Result<Vec<u8>, _>>() {
                
                // Generate BLS signature
                if let Ok(signature) = unstructured.arbitrary::<[u8; BLS_SIGNATURE_LENGTH]>() {
                    
                    // Create block request using property test generators
                    use adjustable_bid_encoding_rs::property_tests::*;
                    
                    // We can't use proptest directly in fuzzing, so create minimal valid data
                    if let Ok(mut minimal_unstructured) = arbitrary::Unstructured::new(&[0u8; 1024]) {
                        if let Ok(adjustment_data) = 
                            adjustable_bid_encoding_rs::types::AdjustmentData::arbitrary(&mut minimal_unstructured) {
                            
                            // Create a minimal valid bid trace
                            let bid_trace = alloy_rpc_types_beacon::relay::BidTrace {
                                slot: 12345,
                                parent_hash: alloy_primitives::B256::from([1u8; 32]),
                                block_hash: alloy_primitives::B256::from([2u8; 32]),
                                builder_pubkey: [3u8; 48],
                                proposer_pubkey: [4u8; 48],
                                proposer_fee_recipient: alloy_primitives::Address::from([5u8; 20]),
                                gas_limit: 25_000_000,
                                gas_used: 20_000_000,
                                value: alloy_primitives::U256::from(1_000_000_000_000_000_000u64),
                            };
                            
                            let request = AdjustableSubmitBlockRequest {
                                message: bid_trace,
                                execution_payload: bytes::Bytes::from(payload_bytes),
                                blobs_bundle: Default::default(),
                                signature,
                                adjustment_data,
                            };
                            
                            // Validate invariants
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
                            
                            // Skip if invariants are violated
                            if InvariantValidator::validate_all_invariants(
                                &proofs,
                                &request.signature,
                                request.message.gas_limit,
                                request.message.gas_used,
                                &addresses,
                            ).is_err() {
                                return;
                            }
                            
                            #[cfg(feature = "ssz")]
                            {
                                // Test SSZ encoding
                                let encoded = request.to_ssz();
                                
                                // Ensure encoding doesn't produce excessive sizes
                                if encoded.len() > 1_000_000 { // 1MB limit
                                    return;
                                }
                                
                                // Test SSZ decoding roundtrip
                                if let Ok(decoded) = AdjustableSubmitBlockRequest::from_ssz_bytes(&encoded) {
                                    // Verify roundtrip consistency
                                    assert_eq!(request.signature, decoded.signature);
                                    assert_eq!(request.message.slot, decoded.message.slot);
                                    assert_eq!(request.message.gas_limit, decoded.message.gas_limit);
                                    assert_eq!(request.adjustment_data.state_root, decoded.adjustment_data.state_root);
                                    
                                    // Test re-encoding
                                    let re_encoded = decoded.to_ssz();
                                    assert_eq!(encoded, re_encoded);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Also test direct deserialization of random bytes
    #[cfg(feature = "ssz")]
    {
        // Limit input size to prevent excessive memory usage
        if data.len() <= 100_000 {
            let _ = AdjustableSubmitBlockRequest::from_ssz_bytes(data);
        }
    }
});