use adjustable_bid_encoding_rs::types::{
    AdjustableSubmitBlockRequest, AdjustableSubmitBlockRequestV4,
};
use eyre::Result;
#[cfg(feature = "ssz")]
use sszb::SszDecode;
use std::fs;

#[cfg(feature = "ssz")]
fn deneb_roundtrip() -> Result<()> {
    println!("Running Deneb roundtrip test...");
    let ssz_bytes = fs::read("../data/adjustableSubmitBlockPayloadDeneb.ssz")?;
    println!("Read {} bytes from file.", ssz_bytes.len());

    let request = <AdjustableSubmitBlockRequest as SszDecode>::from_ssz_bytes(&ssz_bytes)?;
    println!("Successfully deserialized Deneb request.");

    let roundtripped_bytes = request.to_ssz();
    println!("Successfully serialized Deneb request.");

    assert_eq!(ssz_bytes, roundtripped_bytes, "Deneb roundtrip failed");

    println!("✅ Deneb roundtrip successful!");
    Ok(())
}

#[cfg(feature = "ssz")]
fn electra_roundtrip() -> Result<()> {
    println!("\nRunning Electra roundtrip test...");
    let ssz_bytes = fs::read("../data/adjustableSubmitBlockPayloadElectra.ssz")?;
    println!("Read {} bytes from file.", ssz_bytes.len());

    let request = <AdjustableSubmitBlockRequestV4 as SszDecode>::from_ssz_bytes(&ssz_bytes)?;
    println!("Successfully deserialized Electra request.");

    let roundtripped_bytes = request.to_ssz();
    println!("Successfully serialized Electra request.");

    assert_eq!(ssz_bytes, roundtripped_bytes, "Electra roundtrip failed");

    println!("✅ Electra roundtrip successful!");
    Ok(())
}

#[cfg(not(feature = "ssz"))]
fn deneb_roundtrip() -> Result<()> {
    println!("SSZ feature not enabled, skipping Deneb roundtrip test.");
    Ok(())
}

#[cfg(not(feature = "ssz"))]
fn electra_roundtrip() -> Result<()> {
    println!("SSZ feature not enabled, skipping Electra roundtrip test.");
    Ok(())
}

fn main() -> Result<()> {
    deneb_roundtrip()?;
    electra_roundtrip()?;
    Ok(())
}
