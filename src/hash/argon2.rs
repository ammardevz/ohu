use anyhow::{Result, anyhow};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

pub fn hash_argon2(pass: &str) -> Result<String> {
    Argon2::default()
        .hash_password(pass.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|e| anyhow!(e))
}

pub fn verify_argon2(pass: &str, hash: &str) -> Result<()> {
    let hash = PasswordHash::new(hash).map_err(|e| anyhow!(e))?;
    Argon2::default()
        .verify_password(pass.as_bytes(), &hash)
        .map_err(|e| anyhow!(e))
}
