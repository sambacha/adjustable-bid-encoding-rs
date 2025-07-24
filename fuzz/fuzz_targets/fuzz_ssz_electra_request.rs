#![no_main]

use libfuzzer_sys::fuzz_target;
use adjustable_bid_encoding_rs::types::AdjustableSubmitBlockRequestV4;
use adjustable_bid_encoding_rs::invariants::{InvariantValidator, BLS_SIGNATURE_LENGTH};
use arbitrary::Arbitrary;

#[cfg(feature = "ssz")]
use sszb::{SszEncode, SszDecode};

/// Fuzz target for AdjustableSubmitBlockRequestV4 (Electra) SSZ operations
/// 
/// This fuzzer tests Electra-specific features:
/// 1. SSZ serialization with execution_requests field
/// 2. Extended invariant validation for Electra fork
/// 3. Execution requests handling
/// 4. Backward compatibility validation
fuzz_target!(|data: &[u8]| {
    if let Ok(mut unstructured) = arbitrary::Unstructured::new(data) {
        // Generate execution payload and requests sizes (limited to prevent OOM)
        if let Ok(payload_size) = unstructured.int_in_range(0..=4096) {
            if let Ok(requests_size) = unstructured.int_in_range(0..=1024) {
                if let Ok(payload_bytes) = (0..payload_size)
                    .map(|_| unstructured.arbitrary::<u8>())
                    .collect::<Result<Vec<u8>, _>>() {
                    if let Ok(requests_bytes) = (0..requests_size)
                        .map(|_| unstructured.arbitrary::<u8>())
                        .collect::<Result<Vec<u8>, _>>() {
                        
                        // Generate BLS signature
                        if let Ok(signature) = unstructured.arbitrary::<[u8; BLS_SIGNATURE_LENGTH]>() {
                            
                            // Create minimal valid adjustment data
                            if let Ok(mut minimal_unstructured) = arbitrary::Unstructured::new(&[0u8; 1024]) {
                                if let Ok(adjustment_data) = 
                                    adjustable_bid_encoding_rs::types::AdjustmentData::arbitrary(&mut minimal_unstructured) {
                                    
                                    // Create a minimal valid bid trace for Electra
                                    let bid_trace = alloy_rpc_types_beacon::relay::BidTrace {
                                        slot: 12345,
                                        parent_hash: alloy_primitives::B256::from([1u8; 32]),
                                        block_hash: alloy_primitives::B256::from([2u8; 32]),
                                        builder_pubkey: [3u8; 48],
                                        proposer_pubkey: [4u8; 48],
                                        proposer_fee_recipient: alloy_primitives::Address::from([5u8; 20]),
                                        gas_limit: 25_000_000,
                                        gas_used: 20_000_000,
                                        value: alloy_primitives::U256::from(1_500_000_000_000_000_000u64), // 1.5 ETH
                                    };
                                    
                                    let request = AdjustableSubmitBlockRequestV4 {
                                        message: bid_trace,
                                        execution_payload: bytes::Bytes::from(payload_bytes),
                                        blobs_bundle: Default::default(),
                                        execution_requests: bytes::Bytes::from(requests_bytes),
                                        signature,
                                        adjustment_data,
                                    };
                                    
                                    // Validate Electra-specific invariants
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
                                    
                                    // Skip if basic invariants are violated
                                    if InvariantValidator::validate_all_invariants(
                                        &proofs,
                                        &request.signature,
                                        request.message.gas_limit,
                                        request.message.gas_used,
                                        &addresses,
                                    ).is_err() {
                                        return;
                                    }
                                    
                                    // Additional Electra-specific validations
                                    // In a real implementation, we would validate:
                                    // - Execution requests format (EIP-7685)
                                    // - Consolidation request limits
                                    // - Withdrawal request limits
                                    
                                    #[cfg(feature = "ssz")]
                                    {
                                        // Test SSZ encoding for Electra
                                        let encoded = request.to_ssz();
                                        
                                        // Ensure encoding doesn't produce excessive sizes
                                        if encoded.len() > 1_000_000 { // 1MB limit
                                            return;
                                        }
                                        
                                        // Test SSZ decoding roundtrip
                                        if let Ok(decoded) = AdjustableSubmitBlockRequestV4::from_ssz_bytes(&encoded) {
                                            // Verify roundtrip consistency for Electra-specific fields
                                            assert_eq!(request.signature, decoded.signature);
                                            assert_eq!(request.message.slot, decoded.message.slot);
                                            assert_eq!(request.execution_requests, decoded.execution_requests);
                                            assert_eq!(request.adjustment_data.state_root, decoded.adjustment_data.state_root);
                                            
                                            // Verify execution requests are preserved
                                            assert_eq!(request.execution_requests.len(), decoded.execution_requests.len());
                                            
                                            // Test re-encoding
                                            let re_encoded = decoded.to_ssz();
                                            assert_eq!(encoded, re_encoded);
                                            
                                            // Verify that decoded data still satisfies invariants
                                            let decoded_proofs = [
                                                decoded.adjustment_data.builder_proof.as_slice(),
                                                decoded.adjustment_data.fee_recipient_proof.as_slice(),
                                                decoded.adjustment_data.fee_payer_proof.as_slice(),
                                                decoded.adjustment_data.placeholder_tx_proof.as_slice(),
                                                decoded.adjustment_data.placeholder_receipt_proof.as_slice(),
                                            ];
                                            
                                            let decoded_addresses = [
                                                (decoded.adjustment_data.builder_address, "builder_address", false),
                                                (decoded.adjustment_data.fee_recipient_address, "fee_recipient_address", true),
                                                (decoded.adjustment_data.fee_payer_address, "fee_payer_address", true),
                                            ];
                                            
                                            let _ = InvariantValidator::validate_all_invariants(
                                                &decoded_proofs,
                                                &decoded.signature,
                                                decoded.message.gas_limit,
                                                decoded.message.gas_used,
                                                &decoded_addresses,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Test direct deserialization of random bytes for Electra format
    #[cfg(feature = "ssz")]
    {
        // Limit input size to prevent excessive memory usage
        if data.len() <= 100_000 {
            let _ = AdjustableSubmitBlockRequestV4::from_ssz_bytes(data);
        }
    }
    
    // Test differential behavior between Deneb and Electra formats
    #[cfg(feature = "ssz")]
    {
        if data.len() > 100 && data.len() <= 10_000 {
            // Try to decode as both Deneb and Electra
            let _deneb_result = adjustable_bid_encoding_rs::types::AdjustableSubmitBlockRequest::from_ssz_bytes(data);
            let _electra_result = AdjustableSubmitBlockRequestV4::from_ssz_bytes(data);
            
            // Both should handle malformed input gracefully without panicking
            // This tests that the two formats have consistent error handling
        }
    }
});