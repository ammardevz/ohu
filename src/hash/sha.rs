use anyhow::{Result, anyhow};
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

// ============================================================
// SHA-2
// ============================================================

pub fn hash_sha224(input: &str) -> String {
    hex::encode(Sha224::digest(input.as_bytes()))
}

pub fn hash_sha256(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

pub fn hash_sha384(input: &str) -> String {
    hex::encode(Sha384::digest(input.as_bytes()))
}

pub fn hash_sha512(input: &str) -> String {
    hex::encode(Sha512::digest(input.as_bytes()))
}

pub fn verify_sha224(input: &str, hash: &str) -> Result<()> {
    verify_hash(&hash_sha224(input), hash)
}

pub fn verify_sha256(input: &str, hash: &str) -> Result<()> {
    verify_hash(&hash_sha256(input), hash)
}

pub fn verify_sha384(input: &str, hash: &str) -> Result<()> {
    verify_hash(&hash_sha384(input), hash)
}

pub fn verify_sha512(input: &str, hash: &str) -> Result<()> {
    verify_hash(&hash_sha512(input), hash)
}

// ============================================================
// SHA-3
// ============================================================

pub fn hash_sha3_224(input: &str) -> String {
    hex::encode(Sha3_224::digest(input.as_bytes()))
}

pub fn hash_sha3_256(input: &str) -> String {
    hex::encode(Sha3_256::digest(input.as_bytes()))
}

pub fn hash_sha3_384(input: &str) -> String {
    hex::encode(Sha3_384::digest(input.as_bytes()))
}

pub fn hash_sha3_512(input: &str) -> String {
    hex::encode(Sha3_512::digest(input.as_bytes()))
}

pub fn verify_sha3_224(input: &str, hash: &str) -> Result<()> {
    verify_hash(&hash_sha3_224(input), hash)
}

pub fn verify_sha3_256(input: &str, hash: &str) -> Result<()> {
    verify_hash(&hash_sha3_256(input), hash)
}

pub fn verify_sha3_384(input: &str, hash: &str) -> Result<()> {
    verify_hash(&hash_sha3_384(input), hash)
}

pub fn verify_sha3_512(input: &str, hash: &str) -> Result<()> {
    verify_hash(&hash_sha3_512(input), hash)
}

// ============================================================
// Shared verification
// ============================================================

fn verify_hash(computed_hash: &str, expected_hash: &str) -> Result<()> {
    if computed_hash == expected_hash {
        Ok(())
    } else {
        Err(anyhow!("hash mismatch"))
    }
}
