use anyhow::{Result, anyhow};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};

// ============================================================
// ChaCha20-Poly1305
// ============================================================

pub fn encrypt_chacha20_poly1305(input: &str, key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow!("invalid ChaCha20-Poly1305 key"))?;

    let nonce = Nonce::from(*nonce);

    Ok(cipher.encrypt(&nonce, input.as_bytes())?)
}

pub fn decrypt_chacha20_poly1305(
    ciphertext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<String> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow!("invalid ChaCha20-Poly1305 key"))?;

    let nonce = Nonce::from(*nonce);

    let plaintext = cipher.decrypt(&nonce, ciphertext)?;

    Ok(String::from_utf8(plaintext)?)
}

// ============================================================
// XChaCha20-Poly1305
// ============================================================

pub fn encrypt_xchacha20_poly1305(
    input: &str,
    key: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow!("invalid XChaCha20-Poly1305 key"))?;

    let nonce = XNonce::from(*nonce);

    Ok(cipher.encrypt(&nonce, input.as_bytes())?)
}

pub fn decrypt_xchacha20_poly1305(
    ciphertext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<String> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow!("invalid XChaCha20-Poly1305 key"))?;

    let nonce = XNonce::from(*nonce);

    let plaintext = cipher.decrypt(&nonce, ciphertext)?;

    Ok(String::from_utf8(plaintext)?)
}
