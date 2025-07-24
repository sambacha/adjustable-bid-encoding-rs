//! Mathematical invariants and validation for adjustable bid encoding.
//!
//! This module provides compile-time and runtime validation of mathematical
//! properties that must hold for all valid block submissions.

use alloy_primitives::{Address, B256};
use thiserror::Error;

/// Maximum allowed Merkle proof depth (64 levels = 2^64 theoretical tree size)
pub const MAX_PROOF_DEPTH: usize = 64;

/// BLS12-381 signature length (96 bytes)
pub const BLS_SIGNATURE_LENGTH: usize = 96;

/// Maximum gas limit (30M gas - typical Ethereum block limit)
pub const MAX_GAS_LIMIT: u64 = 30_000_000;

#[derive(Error, Debug, PartialEq)]
pub enum InvariantViolation {
    #[error("Proof depth {actual} exceeds maximum {max}")]
    ProofTooDeep { actual: usize, max: usize },
    
    #[error("Invalid signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength { expected: usize, actual: usize },
    
    #[error("Gas used {gas_used} exceeds gas limit {gas_limit}")]
    GasLimitExceeded { gas_used: u64, gas_limit: u64 },
    
    #[error("Gas limit {gas_limit} exceeds maximum {max_limit}")]
    GasLimitTooHigh { gas_limit: u64, max_limit: u64 },
    
    #[error("Merkle proof verification failed for proof of length {proof_len}")]
    MerkleProofFailed { proof_len: usize },
    
    #[error("Hash consistency check failed: {field} hash mismatch")]
    HashConsistencyFailed { field: String },
    
    #[error("Zero address not allowed for {field}")]
    ZeroAddressNotAllowed { field: String },
}

/// Type-safe wrapper for Merkle proofs with compile-time depth bounds
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedProof<const MAX_DEPTH: usize> {
    proof: Vec<Vec<u8>>,
}

impl<const MAX_DEPTH: usize> BoundedProof<MAX_DEPTH> {
    /// Create a new bounded proof, validating depth constraint
    pub fn new(proof: Vec<Vec<u8>>) -> Result<Self, InvariantViolation> {
        if proof.len() > MAX_DEPTH {
            return Err(InvariantViolation::ProofTooDeep {
                actual: proof.len(),
                max: MAX_DEPTH,
            });
        }
        
        Ok(Self { proof })
    }
    
    /// Get the proof elements
    pub fn as_slice(&self) -> &[Vec<u8>] {
        &self.proof
    }
    
    /// Get the proof depth
    pub fn depth(&self) -> usize {
        self.proof.len()
    }
    
    /// Convert to raw proof vector
    pub fn into_raw(self) -> Vec<Vec<u8>> {
        self.proof
    }
}

/// Type-safe wrapper for BLS signatures with compile-time length validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedSignature {
    signature: [u8; BLS_SIGNATURE_LENGTH],
}

impl ValidatedSignature {
    /// Create a validated signature from raw bytes
    pub fn new(signature: [u8; BLS_SIGNATURE_LENGTH]) -> Self {
        Self { signature }
    }
    
    /// Try to create from a slice, validating length
    pub fn from_slice(slice: &[u8]) -> Result<Self, InvariantViolation> {
        if slice.len() != BLS_SIGNATURE_LENGTH {
            return Err(InvariantViolation::InvalidSignatureLength {
                expected: BLS_SIGNATURE_LENGTH,
                actual: slice.len(),
            });
        }
        
        let mut signature = [0u8; BLS_SIGNATURE_LENGTH];
        signature.copy_from_slice(slice);
        Ok(Self { signature })
    }
    
    /// Get the signature bytes
    pub fn as_bytes(&self) -> &[u8; BLS_SIGNATURE_LENGTH] {
        &self.signature
    }
    
    /// Convert to raw bytes
    pub fn into_bytes(self) -> [u8; BLS_SIGNATURE_LENGTH] {
        self.signature
    }
}

/// Type-safe wrapper for state roots with validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateRoot(B256);

impl StateRoot {
    /// Create a new state root
    pub fn new(hash: B256) -> Result<Self, InvariantViolation> {
        // State root cannot be zero (genesis exception not applicable here)
        if hash == B256::ZERO {
            return Err(InvariantViolation::HashConsistencyFailed {
                field: "state_root".to_string(),
            });
        }
        Ok(Self(hash))
    }
    
    /// Get the hash value
    pub fn hash(&self) -> B256 {
        self.0
    }
    
    /// Convert to B256
    pub fn into_hash(self) -> B256 {
        self.0
    }
}

/// Type-safe wrapper for transaction roots
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionRoot(B256);

impl TransactionRoot {
    pub fn new(hash: B256) -> Self {
        Self(hash)
    }
    
    pub fn hash(&self) -> B256 {
        self.0
    }
    
    pub fn into_hash(self) -> B256 {
        self.0
    }
}

/// Type-safe wrapper for receipt roots
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptRoot(B256);

impl ReceiptRoot {
    pub fn new(hash: B256) -> Self {
        Self(hash)
    }
    
    pub fn hash(&self) -> B256 {
        self.0
    }
    
    pub fn into_hash(self) -> B256 {
        self.0
    }
}

/// Type-safe wrapper for validated addresses
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAddress {
    address: Address,
    field_name: String,
}

impl ValidatedAddress {
    /// Create a validated address, rejecting zero address for critical fields
    pub fn new(address: Address, field_name: String, allow_zero: bool) -> Result<Self, InvariantViolation> {
        if !allow_zero && address == Address::ZERO {
            return Err(InvariantViolation::ZeroAddressNotAllowed { field: field_name.clone() });
        }
        
        Ok(Self { address, field_name })
    }
    
    /// Get the address
    pub fn address(&self) -> Address {
        self.address
    }
    
    /// Get the field name for error reporting
    pub fn field_name(&self) -> &str {
        &self.field_name
    }
    
    /// Convert to raw address
    pub fn into_address(self) -> Address {
        self.address
    }
}

/// Gas limit validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedGasLimit {
    gas_limit: u64,
}

impl ValidatedGasLimit {
    /// Create a validated gas limit
    pub fn new(gas_limit: u64) -> Result<Self, InvariantViolation> {
        if gas_limit > MAX_GAS_LIMIT {
            return Err(InvariantViolation::GasLimitTooHigh {
                gas_limit,
                max_limit: MAX_GAS_LIMIT,
            });
        }
        
        Ok(Self { gas_limit })
    }
    
    /// Get the gas limit value
    pub fn value(&self) -> u64 {
        self.gas_limit
    }
    
    /// Validate gas usage against this limit
    pub fn validate_usage(&self, gas_used: u64) -> Result<(), InvariantViolation> {
        if gas_used > self.gas_limit {
            return Err(InvariantViolation::GasLimitExceeded {
                gas_used,
                gas_limit: self.gas_limit,
            });
        }
        Ok(())
    }
}

/// Core mathematical invariants validation
pub struct InvariantValidator;

impl InvariantValidator {
    /// Validate Merkle proof structure (not cryptographic verification)
    pub fn validate_proof_structure(proof: &[Vec<u8>]) -> Result<(), InvariantViolation> {
        if proof.len() > MAX_PROOF_DEPTH {
            return Err(InvariantViolation::ProofTooDeep {
                actual: proof.len(),
                max: MAX_PROOF_DEPTH,
            });
        }
        
        // Each proof element should be 32 bytes (hash length)
        for (i, element) in proof.iter().enumerate() {
            if element.len() != 32 {
                return Err(InvariantViolation::MerkleProofFailed {
                    proof_len: i + 1,
                });
            }
        }
        
        Ok(())
    }
    
    /// Validate signature structure
    pub fn validate_signature_structure(signature: &[u8]) -> Result<(), InvariantViolation> {
        if signature.len() != BLS_SIGNATURE_LENGTH {
            return Err(InvariantViolation::InvalidSignatureLength {
                expected: BLS_SIGNATURE_LENGTH,
                actual: signature.len(),
            });
        }
        Ok(())
    }
    
    /// Validate gas parameters
    pub fn validate_gas_parameters(gas_limit: u64, gas_used: u64) -> Result<(), InvariantViolation> {
        let validated_limit = ValidatedGasLimit::new(gas_limit)?;
        validated_limit.validate_usage(gas_used)?;
        Ok(())
    }
    
    /// Comprehensive validation of all invariants
    pub fn validate_all_invariants(
        proofs: &[&[Vec<u8>]],
        signature: &[u8],
        gas_limit: u64,
        gas_used: u64,
        addresses: &[(Address, &str, bool)], // (address, field_name, allow_zero)
    ) -> Result<(), InvariantViolation> {
        // Validate proof structures
        for proof in proofs {
            Self::validate_proof_structure(proof)?;
        }
        
        // Validate signature
        Self::validate_signature_structure(signature)?;
        
        // Validate gas parameters
        Self::validate_gas_parameters(gas_limit, gas_used)?;
        
        // Validate addresses
        for &(address, field_name, allow_zero) in addresses {
            ValidatedAddress::new(address, field_name.to_string(), allow_zero)?;
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bounded_proof_creation() {
        // Valid proof within bounds
        let proof = vec![vec![0u8; 32], vec![1u8; 32]];
        let bounded = BoundedProof::<64>::new(proof.clone()).unwrap();
        assert_eq!(bounded.depth(), 2);
        assert_eq!(bounded.as_slice(), &proof);
        
        // Proof exceeding bounds
        let large_proof = vec![vec![0u8; 32]; 65];
        let result = BoundedProof::<64>::new(large_proof);
        assert!(matches!(result, Err(InvariantViolation::ProofTooDeep { actual: 65, max: 64 })));
    }
    
    #[test]
    fn test_validated_signature() {
        // Valid signature
        let sig_bytes = [0u8; 96];
        let validated = ValidatedSignature::new(sig_bytes);
        assert_eq!(validated.as_bytes(), &sig_bytes);
        
        // Invalid length
        let invalid_sig = vec![0u8; 95];
        let result = ValidatedSignature::from_slice(&invalid_sig);
        assert!(matches!(result, Err(InvariantViolation::InvalidSignatureLength { .. })));
    }
    
    #[test]
    fn test_state_root_validation() {
        // Valid state root
        let hash = B256::from([1u8; 32]);
        let state_root = StateRoot::new(hash).unwrap();
        assert_eq!(state_root.hash(), hash);
        
        // Zero state root (invalid)
        let result = StateRoot::new(B256::ZERO);
        assert!(matches!(result, Err(InvariantViolation::HashConsistencyFailed { .. })));
    }
    
    #[test]
    fn test_gas_limit_validation() {
        // Valid gas limit
        let gas_limit = ValidatedGasLimit::new(25_000_000).unwrap();
        assert_eq!(gas_limit.value(), 25_000_000);
        
        // Gas limit too high
        let result = ValidatedGasLimit::new(50_000_000);
        assert!(matches!(result, Err(InvariantViolation::GasLimitTooHigh { .. })));
        
        // Valid gas usage
        gas_limit.validate_usage(20_000_000).unwrap();
        
        // Gas usage exceeds limit
        let result = gas_limit.validate_usage(30_000_000);
        assert!(matches!(result, Err(InvariantViolation::GasLimitExceeded { .. })));
    }
    
    #[test]
    fn test_address_validation() {
        // Valid non-zero address
        let addr = Address::from([1u8; 20]);
        let validated = ValidatedAddress::new(addr, "test".to_string(), false).unwrap();
        assert_eq!(validated.address(), addr);
        
        // Zero address when not allowed
        let result = ValidatedAddress::new(Address::ZERO, "test".to_string(), false);
        assert!(matches!(result, Err(InvariantViolation::ZeroAddressNotAllowed { .. })));
        
        // Zero address when allowed
        let validated = ValidatedAddress::new(Address::ZERO, "test".to_string(), true).unwrap();
        assert_eq!(validated.address(), Address::ZERO);
    }
    
    #[test]
    fn test_comprehensive_validation() {
        let proof1 = vec![vec![0u8; 32], vec![1u8; 32]];
        let proof2 = vec![vec![2u8; 32]];
        let empty_proof = vec![];
        
        let proofs = vec![
            proof1.as_slice(),
            proof2.as_slice(),
            empty_proof.as_slice(),
        ];
        let signature = [0u8; 96];
        let addresses = vec![
            (Address::from([1u8; 20]), "builder", false),
            (Address::from([2u8; 20]), "fee_recipient", false),
        ];
        
        // Valid case
        InvariantValidator::validate_all_invariants(
            &proofs,
            &signature,
            25_000_000,
            20_000_000,
            &addresses,
        ).unwrap();
        
        // Invalid signature length
        let invalid_signature = [0u8; 95];
        let result = InvariantValidator::validate_all_invariants(
            &proofs,
            &invalid_signature,
            25_000_000,
            20_000_000,
            &addresses,
        );
        assert!(result.is_err());
    }
}