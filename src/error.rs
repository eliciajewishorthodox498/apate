use std::path::PathBuf;

/// All errors that can occur in the Apate pipeline.
#[derive(Debug, thiserror::Error)]
pub enum ApateError {
    #[error("Failed to parse source file: {path}")]
    ParseError {
        path: PathBuf,
        #[source]
        source: syn::Error,
    },

    #[error("Key file not found: {0}")]
    KeyNotFound(PathBuf),

    #[error("Invalid key file (expected 32 bytes, got {0})")]
    InvalidKeyLength(usize),

    #[error("Manifest decryption failed — wrong key?")]
    ManifestDecryptionFailed,

    #[error("Round-trip verification failed for {path}: hashes differ")]
    VerificationFailed { path: PathBuf },

    #[error("Pass '{pass}' failed: {reason}")]
    PassFailed { pass: String, reason: String },

    #[error("Unknown pass: {0}")]
    UnknownPass(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ApateError>;
