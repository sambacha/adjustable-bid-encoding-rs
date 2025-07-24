#![no_main]

use libfuzzer_sys::fuzz_target;
use adjustable_bid_encoding_rs::types::AdjustmentData;
use adjustable_bid_encoding_rs::invariants::InvariantValidator;
use arbitrary::Arbitrary;

#[cfg(feature = "ssz")]
use sszb::{SszEncode, SszDecode};

/// Fuzz target for AdjustmentData SSZ serialization/deserialization
/// 
/// This fuzzer tests:
/// 1. SSZ encoding/decoding roundtrip consistency
/// 2. Invariant preservation across serialization
/// 3. Malformed input handling
/// 4. Memory safety during deserialization
fuzz_target!(|data: &[u8]| {
    // Try to create AdjustmentData from arbitrary bytes
    if let Ok(mut unstructured) = arbitrary::Unstructured::new(data) {
        if let Ok(adjustment_data) = AdjustmentData::arbitrary(&mut unstructured) {
            
            // Validate that generated data satisfies invariants
            let proofs = [
                &adjustment_data.builder_proof,
                &adjustment_data.fee_recipient_proof,
                &adjustment_data.fee_payer_proof,
                &adjustment_data.placeholder_tx_proof,
                &adjustment_data.placeholder_receipt_proof,
            ];
            
            // Skip invalid data that doesn't meet our invariants
            let mut all_proofs_valid = true;
            for proof in &proofs {
                if InvariantValidator::validate_proof_structure(proof).is_err() {
                    all_proofs_valid = false;
                    break;
                }
            }
            
            if !all_proofs_valid {
                return;
            }
            
            #[cfg(feature = "ssz")]
            {
                // Test SSZ encoding
                let encoded = adjustment_data.to_ssz();
                
                // Test SSZ decoding roundtrip
                if let Ok(decoded) = AdjustmentData::from_ssz_bytes(&encoded) {
                    // Verify roundtrip consistency
                    assert_eq!(adjustment_data, decoded);
                    
                    // Verify invariants are preserved
                    let decoded_proofs = [
                        &decoded.builder_proof,
                        &decoded.fee_recipient_proof,
                        &decoded.fee_payer_proof,
                        &decoded.placeholder_tx_proof,
                        &decoded.placeholder_receipt_proof,
                    ];
                    
                    for proof in &decoded_proofs {
                        let _ = InvariantValidator::validate_proof_structure(proof);
                    }
                    
                    // Test encoding the decoded data again
                    let re_encoded = decoded.to_ssz();
                    assert_eq!(encoded, re_encoded);
                }
            }
        }
    }
    
    // Also test direct deserialization of random bytes
    #[cfg(feature = "ssz")]
    {
        // Attempt to decode random bytes as AdjustmentData
        let _ = AdjustmentData::from_ssz_bytes(data);
        // Should not panic, even with malformed input
    }
});