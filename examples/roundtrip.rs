use eyre::Result;

fn main() -> Result<()> {
    #[cfg(feature = "ssz")]
    {
        println!("SSZ feature is enabled but manual implementation is required.");
        println!("The types contain nested external types that don't implement SSZ traits.");
        println!("This example is a placeholder for future SSZ support.");
    }
    
    #[cfg(not(feature = "ssz"))]
    {
        println!("SSZ feature not enabled.");
        println!("To enable SSZ support, run with: cargo run --features ssz --example roundtrip");
    }
    
    Ok(())
}