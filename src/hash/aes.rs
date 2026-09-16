use aes::{Aes128, Aes256};
use anyhow::{Result, anyhow};
use ccm::{
    Ccm,
    aead::{Aead, KeyInit},
    consts::{U13, U16},
};

type Aes128Ccm = Ccm<Aes128, U16, U13>;
type Aes256Ccm = Ccm<Aes256, U16, U13>;

// ============================================================
// AES-128-GCM
// ============================================================

use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce as GcmNonce};

pub fn encrypt_aes_gcm_128(input: &str, key: &[u8; 16], nonce: &[u8; 12]) -> Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| anyhow!("invalid AES-128 key"))?;

    let nonce = GcmNonce::from(*nonce);

    Ok(cipher.encrypt(&nonce, input.as_bytes())?)
}

pub fn decrypt_aes_gcm_128(ciphertext: &[u8], key: &[u8; 16], nonce: &[u8; 12]) -> Result<String> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| anyhow!("invalid AES-128 key"))?;

    let nonce = GcmNonce::from(*nonce);

    let plaintext = cipher.decrypt(&nonce, ciphertext)?;

    Ok(String::from_utf8(plaintext)?)
}

pub fn encrypt_aes_gcm_256(input: &str, key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow!("invalid AES-256 key"))?;

    let nonce = GcmNonce::from(*nonce);

    Ok(cipher.encrypt(&nonce, input.as_bytes())?)
}

pub fn decrypt_aes_gcm_256(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow!("invalid AES-256 key"))?;

    let nonce = GcmNonce::from(*nonce);

    let plaintext = cipher.decrypt(&nonce, ciphertext)?;

    Ok(String::from_utf8(plaintext)?)
}

// ============================================================
// AES-128-CCM
// ============================================================

pub fn encrypt_aes_ccm_128(input: &str, key: &[u8; 16], nonce: &[u8; 13]) -> Result<Vec<u8>> {
    let cipher = Aes128Ccm::new_from_slice(key).map_err(|_| anyhow!("invalid AES-128 key"))?;

    let nonce = nonce.into();

    Ok(cipher.encrypt(nonce, input.as_bytes())?)
}

pub fn decrypt_aes_ccm_128(ciphertext: &[u8], key: &[u8; 16], nonce: &[u8; 13]) -> Result<String> {
    let cipher = Aes128Ccm::new_from_slice(key).map_err(|_| anyhow!("invalid AES-128 key"))?;

    let nonce = nonce.into();

    let plaintext = cipher.decrypt(nonce, ciphertext)?;

    Ok(String::from_utf8(plaintext)?)
}

// ============================================================
// AES-256-CCM
// ============================================================

pub fn encrypt_aes_ccm_256(input: &str, key: &[u8; 32], nonce: &[u8; 13]) -> Result<Vec<u8>> {
    let cipher = Aes256Ccm::new_from_slice(key).map_err(|_| anyhow!("invalid AES-256 key"))?;

    let nonce = nonce.into();

    Ok(cipher.encrypt(nonce, input.as_bytes())?)
}

pub fn decrypt_aes_ccm_256(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 13]) -> Result<String> {
    let cipher = Aes256Ccm::new_from_slice(key).map_err(|_| anyhow!("invalid AES-256 key"))?;

    let nonce = nonce.into();

    let plaintext = cipher.decrypt(nonce, ciphertext)?;

    Ok(String::from_utf8(plaintext)?)
}
