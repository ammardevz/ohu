use anyhow::{Result, anyhow};

pub fn hash_blake3(input: &str) -> Result<String> {
    Ok(blake3::hash(input.as_bytes()).to_hex().to_string())
}

pub fn verify_blake3(input: &str, hash: &str) -> Result<()> {
    let computed_hash = hash_blake3(input)?;

    if computed_hash == hash {
        Ok(())
    } else {
        Err(anyhow!("hash mismatch"))
    }
}
