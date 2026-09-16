use anyhow::{Result, anyhow};
use clap::Parser;
use rand::Rng;
use std::fs;

use crate::{
    cli::Cli,
    hash::{
        aes::*,
        argon2::{hash_argon2, verify_argon2},
        bcrypt::{hash_bcrypt, verify_bcrypt},
        blake3::{hash_blake3, verify_blake3},
        chacha::*,
        md5::{hash_md5, verify_md5},
        sha::*,
        xxhash::{hash_xxhash, verify_hash as verify_xxh3},
    },
};

pub mod cli;
pub mod hash;

fn random_nonce<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::rng().fill_bytes(&mut buf);
    buf
}

fn parse_key<const N: usize>(hex_key: &str) -> Result<[u8; N]> {
    hex::decode(hex_key)?
        .try_into()
        .map_err(|_| anyhow!("key must be {N} bytes"))
}

fn main() -> Result<()> {
    let parser = Cli::parse();

    match parser.command {
        cli::Command::Hash { algorithm, input } => {
            let result = match algorithm {
                cli::HashAlgorithm::Argon2 => hash_argon2(&input),
                cli::HashAlgorithm::Bcrypt => hash_bcrypt(&input),
                cli::HashAlgorithm::Md5 => hash_md5(&input),
                cli::HashAlgorithm::Blake3 => hash_blake3(&input),
                cli::HashAlgorithm::Xxh3 => hash_xxhash(&input),
                cli::HashAlgorithm::Sha224 => Ok(hash_sha224(&input)),
                cli::HashAlgorithm::Sha256 => Ok(hash_sha256(&input)),
                cli::HashAlgorithm::Sha384 => Ok(hash_sha384(&input)),
                cli::HashAlgorithm::Sha512 => Ok(hash_sha512(&input)),
                cli::HashAlgorithm::Sha3_224 => Ok(hash_sha3_224(&input)),
                cli::HashAlgorithm::Sha3_256 => Ok(hash_sha3_256(&input)),
                cli::HashAlgorithm::Sha3_384 => Ok(hash_sha3_384(&input)),
                cli::HashAlgorithm::Sha3_512 => Ok(hash_sha3_512(&input)),
            }?;
            println!("{result}");
        }

        cli::Command::Verify {
            algorithm,
            input,
            hash,
        } => {
            let result = match algorithm {
                cli::HashAlgorithm::Argon2 => verify_argon2(&input, &hash),
                cli::HashAlgorithm::Bcrypt => verify_bcrypt(&input, &hash),
                cli::HashAlgorithm::Md5 => verify_md5(&input, &hash),
                cli::HashAlgorithm::Blake3 => verify_blake3(&input, &hash),
                cli::HashAlgorithm::Xxh3 => verify_xxh3(&input, &hash),
                cli::HashAlgorithm::Sha224 => verify_sha224(&input, &hash),
                cli::HashAlgorithm::Sha256 => verify_sha256(&input, &hash),
                cli::HashAlgorithm::Sha384 => verify_sha384(&input, &hash),
                cli::HashAlgorithm::Sha512 => verify_sha512(&input, &hash),
                cli::HashAlgorithm::Sha3_224 => verify_sha3_224(&input, &hash),
                cli::HashAlgorithm::Sha3_256 => verify_sha3_256(&input, &hash),
                cli::HashAlgorithm::Sha3_384 => verify_sha3_384(&input, &hash),
                cli::HashAlgorithm::Sha3_512 => verify_sha3_512(&input, &hash),
            };
            match result {
                Ok(()) => println!("valid"),
                Err(e) => println!("invalid: {e}"),
            }
        }

        cli::Command::Encrypt {
            algorithm,
            key,
            input,
            output,
        } => {
            let payload = match algorithm {
                cli::EncryptionAlgorithm::Aes128Gcm => {
                    let key = parse_key::<16>(&key)?;
                    let nonce = random_nonce::<12>();
                    [nonce.to_vec(), encrypt_aes_gcm_128(&input, &key, &nonce)?].concat()
                }
                cli::EncryptionAlgorithm::Aes256Gcm => {
                    let key = parse_key::<32>(&key)?;
                    let nonce = random_nonce::<12>();
                    [nonce.to_vec(), encrypt_aes_gcm_256(&input, &key, &nonce)?].concat()
                }
                cli::EncryptionAlgorithm::ChaCha20Poly1305 => {
                    let key = parse_key::<32>(&key)?;
                    let nonce = random_nonce::<12>();
                    [
                        nonce.to_vec(),
                        encrypt_chacha20_poly1305(&input, &key, &nonce)?,
                    ]
                    .concat()
                }
                cli::EncryptionAlgorithm::XChaCha20Poly1305 => {
                    let key = parse_key::<32>(&key)?;
                    let nonce = random_nonce::<24>();
                    [
                        nonce.to_vec(),
                        encrypt_xchacha20_poly1305(&input, &key, &nonce)?,
                    ]
                    .concat()
                }
                cli::EncryptionAlgorithm::Aes128Ccm => {
                    let key = parse_key::<16>(&key)?;
                    let nonce = random_nonce::<13>();
                    [nonce.to_vec(), encrypt_aes_ccm_128(&input, &key, &nonce)?].concat()
                }
                cli::EncryptionAlgorithm::Aes256Ccm => {
                    let key = parse_key::<32>(&key)?;
                    let nonce = random_nonce::<13>();
                    [nonce.to_vec(), encrypt_aes_ccm_256(&input, &key, &nonce)?].concat()
                }
            };
            fs::write(&output, payload)?;
            println!("wrote {output}");
        }

        cli::Command::Decrypt {
            algorithm,
            key,
            input,
            output,
        } => {
            let data = fs::read(&input)?;
            let plaintext = match algorithm {
                cli::EncryptionAlgorithm::Aes128Gcm => {
                    let key = parse_key::<16>(&key)?;
                    let (nonce, ct) = data.split_at(12);
                    decrypt_aes_gcm_128(ct, &key, &nonce.try_into()?)?
                }
                cli::EncryptionAlgorithm::Aes256Gcm => {
                    let key = parse_key::<32>(&key)?;
                    let (nonce, ct) = data.split_at(12);
                    decrypt_aes_gcm_256(ct, &key, &nonce.try_into()?)?
                }
                cli::EncryptionAlgorithm::ChaCha20Poly1305 => {
                    let key = parse_key::<32>(&key)?;
                    let (nonce, ct) = data.split_at(12);
                    decrypt_chacha20_poly1305(ct, &key, &nonce.try_into()?)?
                }
                cli::EncryptionAlgorithm::XChaCha20Poly1305 => {
                    let key = parse_key::<32>(&key)?;
                    let (nonce, ct) = data.split_at(24);
                    decrypt_xchacha20_poly1305(ct, &key, &nonce.try_into()?)?
                }
                cli::EncryptionAlgorithm::Aes128Ccm => {
                    let key = parse_key::<16>(&key)?;
                    let (nonce, ct) = data.split_at(13);
                    decrypt_aes_ccm_128(ct, &key, &nonce.try_into()?)?
                }
                cli::EncryptionAlgorithm::Aes256Ccm => {
                    let key = parse_key::<32>(&key)?;
                    let (nonce, ct) = data.split_at(13);
                    decrypt_aes_ccm_256(ct, &key, &nonce.try_into()?)?
                }
            };
            fs::write(&output, plaintext)?;
            println!("wrote {output}");
        }

        cli::Command::VerifyFileIntegrity {
            algorithm,
            input,
            hash,
        } => {
            let data = fs::read_to_string(&input)?;
            let result = match algorithm {
                cli::HashAlgorithm::Argon2 => verify_argon2(&data, &hash),
                cli::HashAlgorithm::Bcrypt => verify_bcrypt(&data, &hash),
                cli::HashAlgorithm::Md5 => verify_md5(&data, &hash),
                cli::HashAlgorithm::Blake3 => verify_blake3(&data, &hash),
                cli::HashAlgorithm::Xxh3 => verify_xxh3(&data, &hash),
                cli::HashAlgorithm::Sha224 => verify_sha224(&data, &hash),
                cli::HashAlgorithm::Sha256 => verify_sha256(&data, &hash),
                cli::HashAlgorithm::Sha384 => verify_sha384(&data, &hash),
                cli::HashAlgorithm::Sha512 => verify_sha512(&data, &hash),
                cli::HashAlgorithm::Sha3_224 => verify_sha3_224(&data, &hash),
                cli::HashAlgorithm::Sha3_256 => verify_sha3_256(&data, &hash),
                cli::HashAlgorithm::Sha3_384 => verify_sha3_384(&data, &hash),
                cli::HashAlgorithm::Sha3_512 => verify_sha3_512(&data, &hash),
            };
            match result {
                Ok(()) => println!("valid"),
                Err(e) => println!("invalid: {e}"),
            }
        }

        cli::Command::CompareFile { first, second } => {
            let a = blake3::hash(&fs::read(&first)?);
            let b = blake3::hash(&fs::read(&second)?);
            println!("{}", if a == b { "identical" } else { "different" });
        }
    };

    Ok(())
}
