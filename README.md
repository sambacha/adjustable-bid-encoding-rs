# Adjustable Bid Encoding for Rust

This crate provides a Rust implementation of adjustable Ethereum block submission requests for use by block builders. It is compatible with the Go reference implementation and supports current and upcoming Ethereum forks.

## Overview

* Submission of block data using adjustable request formats.
* Compatibility with Ethereum's Deneb and Electra forks.
* Optional SSZ (SimpleSerialize) encoding/decoding.
* Full integration with the [`alloy-rs`](https://github.com/alloy-rs) Ethereum ecosystem.

### Network Support

| Feature               | Description                                                      |
| --------------------- | ---------------------------------------------------------------- |
| **Deneb Support**     | `AdjustableSubmitBlockRequest` type for Deneb fork submission    |
| **Electra Support**   | `AdjustableSubmitBlockRequestV4` for Electra fork submission     |
| **SSZ Serialization** | Optional SSZ support via `sszb`, behind a crate feature          |
| **Alloy Integration** | Uses types from the `alloy-rs` ecosystem for Ethereum primitives |

## Installation

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
adjustable-bid-encoding-rs = "0.1"
```

To enable SSZ serialization, use the optional `ssz` feature:

```toml
[dependencies]
adjustable-bid-encoding-rs = { version = "0.1", features = ["ssz"] }
```

### Adjustable Bid Encoding

```rust
use adjustable_bid_encoding_rs::types::{AdjustableSubmitBlockRequest, AdjustmentData};
use alloy_primitives::{Address, B256};

// Create adjustment data
let adjustment_data = AdjustmentData {
    state_root: B256::default(),
    transactions_root: B256::default(),
    receipts_root: B256::default(),
    builder_address: Address::default(),
    builder_proof: vec![],
    fee_recipient_address: Address::default(),
    fee_recipient_proof: vec![],
    fee_payer_address: Address::default(),
    fee_payer_proof: vec![],
    placeholder_tx_proof: vec![],
    placeholder_receipt_proof: vec![],
};

// Construct the submission request
let request = AdjustableSubmitBlockRequest {
    message: Default::default(),
    execution_payload: Default::default(),
    blobs_bundle: Default::default(),
    signature: [0; 96],
    adjustment_data,
};
```

> **Note**
> The `AdjustableSubmitBlockRequestV4` type can be used similarly for Electra fork compatibility.

## SSZ Support

SSZ serialization and deserialization is provided via the [`sszb`](https://github.com/sigp/ssz-rs) library. This is an optional feature and must be enabled explicitly.

```toml
[dependencies]
adjustable-bid-encoding-rs = { version = "0.1", features = ["ssz"] }
```

Once enabled, types like `AdjustableSubmitBlockRequest` and `AdjustmentData` will implement `Encode` and `Decode`.

## License

GPL-2.0
