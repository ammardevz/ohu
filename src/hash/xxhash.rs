use anyhow::{Result, anyhow};
use xxhash_rust::xxh3::xxh3_64;

pub fn hash_xxhash(input: &str) -> Result<String> {
    Ok(format!("{:016x}", xxh3_64(input.as_bytes())))
}

pub fn verify_hash(input: &str, hash: &str) -> Result<()> {
    if hash_xxhash(input)? == hash {
        Ok(())
    } else {
        Err(anyhow!("hash mismatch"))
    }
}
