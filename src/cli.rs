use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser, Clone)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Debug, Subcommand, Clone)]
pub enum Command {
    Hash {
        #[arg(short, long, value_enum, default_value_t = HashAlgorithm::Argon2)]
        algorithm: HashAlgorithm,

        input: String,
    },

    Verify {
        #[arg(short, long, value_enum)]
        algorithm: HashAlgorithm,

        input: String,
        hash: String,
    },

    Encrypt {
        #[arg(short, long, value_enum)]
        algorithm: EncryptionAlgorithm,

        #[arg(short, long)]
        key: String, // hex-encoded

        input: String,
        output: String,
    },

    Decrypt {
        #[arg(short, long, value_enum)]
        algorithm: EncryptionAlgorithm,

        #[arg(short, long)]
        key: String, // hex-encoded

        input: String,
        output: String,
    },

    VerifyFileIntegrity {
        #[arg(short, long, value_enum)]
        algorithm: HashAlgorithm,

        input: String,
        hash: String,
    },

    CompareFile {
        first: String,
        second: String,
    },
}

#[derive(Debug, Clone, ValueEnum)]
pub enum HashAlgorithm {
    Argon2,
    Bcrypt,

    Md5,
    Blake3,
    Xxh3,

    Sha224,
    Sha256,
    Sha384,
    Sha512,

    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum EncryptionAlgorithm {
    Aes128Gcm,
    Aes256Gcm,

    ChaCha20Poly1305,
    XChaCha20Poly1305,

    Aes128Ccm,
    Aes256Ccm,
}
