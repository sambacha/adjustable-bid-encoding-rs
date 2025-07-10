use alloy_primitives::{Address, B256};
#[cfg(feature = "ssz")]
use bytes::{Buf, BufMut};
#[cfg(feature = "ssz")]
use sszb::{SszDecode, SszEncode};
#[cfg(feature = "ssz")]
use sszb_derive::{SszbDecode, SszbEncode};

#[cfg_attr(
    feature = "ssz",
    derive(Debug, Clone, PartialEq, Eq, SszbEncode, SszbDecode)
)]
#[cfg_attr(not(feature = "ssz"), derive(Debug, Clone, PartialEq, Eq))]
pub struct AdjustmentData {
    pub state_root: B256,
    pub transactions_root: B256,
    pub receipts_root: B256,
    pub builder_address: Address,
    pub builder_proof: Vec<Vec<u8>>,
    pub fee_recipient_address: Address,
    pub fee_recipient_proof: Vec<Vec<u8>>,
    pub fee_payer_address: Address,
    pub fee_payer_proof: Vec<Vec<u8>>,
    pub placeholder_tx_proof: Vec<Vec<u8>>,
    pub placeholder_receipt_proof: Vec<Vec<u8>>,
}

impl Default for AdjustmentData {
    fn default() -> Self {
        Self {
            state_root: B256::default(),
            transactions_root: B256::default(),
            receipts_root: B256::default(),
            builder_address: Address::default(),
            builder_proof: Vec::new(),
            fee_recipient_address: Address::default(),
            fee_recipient_proof: Vec::new(),
            fee_payer_address: Address::default(),
            fee_payer_proof: Vec::new(),
            placeholder_tx_proof: Vec::new(),
            placeholder_receipt_proof: Vec::new(),
        }
    }
}
