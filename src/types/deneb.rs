use crate::types::adjustment_data::AdjustmentData;
use alloy_eips::eip4844::BlobTransactionSidecar;
use alloy_rpc_types_beacon::relay::BidTrace;
use bytes::Bytes;
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
pub struct AdjustableSubmitBlockRequest {
    pub message: BidTrace,
    pub execution_payload: Bytes, // Simplified to bytes for now
    pub blobs_bundle: BlobTransactionSidecar,
    pub signature: [u8; 96],
    pub adjustment_data: AdjustmentData,
}

impl Default for AdjustableSubmitBlockRequest {
    fn default() -> Self {
        Self {
            message: Default::default(),
            execution_payload: Bytes::new(),
            blobs_bundle: Default::default(),
            signature: [0; 96],
            adjustment_data: Default::default(),
        }
    }
}
