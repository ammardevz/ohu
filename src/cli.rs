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
        input: String,
        hash: String,
    },

    Encrypt {
        #[arg(short, long, value_enum)]
        algorithm: EncryptionAlgorithm,

        input: String,
        output: String,
    },

    Decrypt {
        #[arg(short, long, value_enum)]
        algorithm: EncryptionAlgorithm,

        input: String,
        output: String,
    },

    VerifyFileIntegrity {
        input: String,
    },

    CompareFile {
        first: String,
        second: String,
    },
}

#[derive(Debug, Clone, ValueEnum)]
pub enum HashAlgorithm {
    Argon2,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum EncryptionAlgorithm {
    Aes256,
    ChaCha20,
}
