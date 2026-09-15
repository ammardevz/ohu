use anyhow::{Result, anyhow};

pub fn hash_md5(input: &str) -> Result<String> {
    Ok(fast_md5::digest(input.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub fn verify_md5(input: &str, hash: &str) -> Result<()> {
    if hash_md5(input)? == hash {
        return Ok(());
    } else {
        Err(anyhow!("hash mismatch"))
    }
}
