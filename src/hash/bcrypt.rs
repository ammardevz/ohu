use anyhow::{Result, anyhow};
use bcrypt::{DEFAULT_COST, hash, verify};

pub fn hash_bcrypt(pass: &str) -> Result<String> {
    hash(pass, DEFAULT_COST).map_err(|err| anyhow!(err))
}

pub fn verify_bcrypt(pass: &str, hash: &str) -> Result<()> {
    let valid = verify(pass, hash).map_err(|err| anyhow!(err))?;

    if valid {
        Ok(())
    } else {
        Err(anyhow!("invalid password"))
    }
}
