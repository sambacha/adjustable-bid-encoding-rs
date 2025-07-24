#![no_main]

use libfuzzer_sys::fuzz_target;
use adjustable_bid_encoding_rs::invariants::*;
use alloy_primitives::{Address, B256};
use arbitrary::Arbitrary;

/// Fuzz target for invariant validation functions
/// 
/// This fuzzer tests:
/// 1. Invariant validation with malformed inputs
/// 2. Edge cases in proof structure validation
/// 3. Gas parameter validation edge cases
/// 4. Address validation logic
/// 5. Type-safe wrapper robustness
fuzz_target!(|data: &[u8]| {
    if let Ok(mut unstructured) = arbitrary::Unstructured::new(data) {
        
        // Test proof structure validation with arbitrary proofs
        if let Ok(num_proofs) = unstructured.int_in_range(0..=10) {
            let mut proofs = Vec::new();
            
            for _ in 0..num_proofs {
                if let Ok(proof_len) = unstructured.int_in_range(0..=100) {
                    let mut proof = Vec::new();
                    
                    for _ in 0..proof_len {
                        if let Ok(element_len) = unstructured.int_in_range(0..=64) {
                            if let Ok(element) = (0..element_len)
                                .map(|_| unstructured.arbitrary::<u8>())
                                .collect::<Result<Vec<u8>, _>>() {
                                proof.push(element);
                            }
                        }
                    }
                    proofs.push(proof);
                }
            }
            
            // Test each proof individually
            for proof in &proofs {
                let _ = InvariantValidator::validate_proof_structure(proof);
                
                // Test BoundedProof creation
                let _ = BoundedProof::<MAX_PROOF_DEPTH>::new(proof.clone());
                let _ = BoundedProof::<32>::new(proof.clone());
                let _ = BoundedProof::<128>::new(proof.clone());
            }
        }
        
        // Test signature validation with arbitrary signatures
        if let Ok(sig_len) = unstructured.int_in_range(0..=200) {
            if let Ok(signature) = (0..sig_len)
                .map(|_| unstructured.arbitrary::<u8>())
                .collect::<Result<Vec<u8>, _>>() {
                
                let _ = InvariantValidator::validate_signature_structure(&signature);
                
                // Test ValidatedSignature creation
                if signature.len() == BLS_SIGNATURE_LENGTH {
                    let _ = ValidatedSignature::from_slice(&signature);
                }
            }
        }
        
        // Test gas parameter validation
        if let Ok(gas_limit) = unstructured.arbitrary::<u64>() {
            if let Ok(gas_used) = unstructured.arbitrary::<u64>() {
                let _ = InvariantValidator::validate_gas_parameters(gas_limit, gas_used);
                
                // Test ValidatedGasLimit
                let _ = ValidatedGasLimit::new(gas_limit);
                
                if let Ok(validated_limit) = ValidatedGasLimit::new(gas_limit.min(MAX_GAS_LIMIT)) {
                    let _ = validated_limit.validate_usage(gas_used);
                }
            }
        }
        
        // Test address validation
        if let Ok(addr_bytes) = unstructured.arbitrary::<[u8; 20]>() {
            let address = Address::from(addr_bytes);
            
            // Test with different field names and zero-allowance settings
            let field_names = ["builder", "fee_recipient", "fee_payer", "test_field"];
            let allow_zero_options = [true, false];
            
            for &field_name in &field_names {
                for &allow_zero in &allow_zero_options {
                    let _ = ValidatedAddress::new(
                        address, 
                        field_name.to_string(), 
                        allow_zero
                    );
                }
            }
        }
        
        // Test hash validation
        if let Ok(hash_bytes) = unstructured.arbitrary::<[u8; 32]>() {
            let hash = B256::from(hash_bytes);
            
            let _ = StateRoot::new(hash);
            let _ = TransactionRoot::new(hash);
            let _ = ReceiptRoot::new(hash);
        }
        
        // Test comprehensive validation with arbitrary data
        if data.len() > 100 {
            // Create some test proofs
            let test_proofs = vec![
                vec![vec![0u8; 32]].as_slice(),
                vec![vec![1u8; 32], vec![2u8; 32]].as_slice(),
                vec![].as_slice(),
            ];
            
            // Create test signature
            let test_signature = [0u8; BLS_SIGNATURE_LENGTH];
            
            // Create test addresses
            let test_addresses = vec![
                (Address::from([1u8; 20]), "test1", false),
                (Address::from([2u8; 20]), "test2", true),
                (Address::ZERO, "test3", true),
            ];
            
            // Test comprehensive validation
            let _ = InvariantValidator::validate_all_invariants(
                &test_proofs,
                &test_signature,
                25_000_000,
                20_000_000,
                &test_addresses,
            );
        }
        
        // Test edge cases for bounded types
        if let Ok(depth) = unstructured.int_in_range(60..=70) {
            let large_proof = vec![vec![0u8; 32]; depth];
            
            // This should handle both valid and invalid depths
            let _ = BoundedProof::<64>::new(large_proof.clone());
            let _ = BoundedProof::<32>::new(large_proof.clone());
            let _ = BoundedProof::<100>::new(large_proof);
        }
        
        // Test type conversions and operations
        if let Ok(hash_bytes) = unstructured.arbitrary::<[u8; 32]>() {
            let hash = B256::from(hash_bytes);
            
            if let Ok(state_root) = StateRoot::new(hash) {
                // Test conversions
                let extracted_hash = state_root.hash();
                assert_eq!(extracted_hash, hash);
                
                let converted_back = state_root.into_hash();
                assert_eq!(converted_back, hash);
            }
            
            // Test other root types
            let tx_root = TransactionRoot::new(hash);
            let receipt_root = ReceiptRoot::new(hash);
            
            assert_eq!(tx_root.hash(), hash);
            assert_eq!(receipt_root.hash(), hash);
        }
        
        // Test ValidatedAddress operations
        if let Ok(addr_bytes) = unstructured.arbitrary::<[u8; 20]>() {
            let address = Address::from(addr_bytes);
            
            if let Ok(validated) = ValidatedAddress::new(
                address, 
                "test_field".to_string(), 
                true
            ) {
                assert_eq!(validated.address(), address);
                assert_eq!(validated.field_name(), "test_field");
                
                let converted_back = validated.into_address();
                assert_eq!(converted_back, address);
            }
        }
    }
});