use std::path::{Path, PathBuf};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use serde::{Deserialize, Serialize};

use crate::error::{ApateError, Result};
use crate::key;
use crate::passes::PassRecord;
use crate::utils::crypto;

/// Top-level manifest storing everything needed to reverse all transforms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub files: Vec<FileManifest>,
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            version: 1,
            files: Vec::new(),
        }
    }
}

impl Manifest {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Per-file manifest: the original hash and ordered list of applied transforms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifest {
    pub relative_path: PathBuf,
    /// BLAKE3 hash of the original source (hex-encoded for JSON readability).
    pub original_hash: String,
    pub passes: Vec<PassRecord>,
}

/// Encrypt a manifest with AES-256-GCM using a key derived from the master key.
///
/// The nonce is deterministic (derived from the AES key) so the same key
/// always produces the same encrypted manifest for the same input.
pub fn encrypt_manifest(manifest: &Manifest, master_key: &[u8; 32]) -> Result<Vec<u8>> {
    let aes_key = key::derive_subkey(master_key, key::AES_CONTEXT);
    let nonce_bytes = derive_nonce(&aes_key);

    let plaintext = serde_json::to_vec(manifest)
        .map_err(|e| ApateError::PassFailed {
            pass: "manifest".into(),
            reason: format!("serialization failed: {e}"),
        })?;

    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .expect("AES-256-GCM key is always 32 bytes");
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| ApateError::ManifestDecryptionFailed)
}

/// Decrypt a manifest with AES-256-GCM using a key derived from the master key.
pub fn decrypt_manifest(data: &[u8], master_key: &[u8; 32]) -> Result<Manifest> {
    let aes_key = key::derive_subkey(master_key, key::AES_CONTEXT);
    let nonce_bytes = derive_nonce(&aes_key);

    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .expect("AES-256-GCM key is always 32 bytes");
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, data)
        .map_err(|_| ApateError::ManifestDecryptionFailed)?;

    serde_json::from_slice(&plaintext).map_err(|e| ApateError::PassFailed {
        pass: "manifest".into(),
        reason: format!("deserialization failed: {e}"),
    })
}

/// Save encrypted manifest bytes to a `.apate` file.
pub fn save_manifest(data: &[u8], path: &Path) -> Result<()> {
    std::fs::write(path, data)?;
    Ok(())
}

/// Load encrypted manifest bytes from a `.apate` file.
pub fn load_manifest(path: &Path) -> Result<Vec<u8>> {
    Ok(std::fs::read(path)?)
}

/// Derive a deterministic 12-byte nonce from the AES key.
///
/// Uses `BLAKE3(aes_key || "nonce")` truncated to 12 bytes.
fn derive_nonce(aes_key: &[u8; 32]) -> [u8; 12] {
    let mut input = aes_key.to_vec();
    input.extend_from_slice(b"nonce");
    let hash = crypto::blake3_hash(&input);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&hash[..12]);
    nonce
}
