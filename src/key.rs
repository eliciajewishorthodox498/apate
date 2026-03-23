use std::path::Path;

use rand::RngCore;

use crate::error::{ApateError, Result};

/// BLAKE3 key derivation context strings.
pub const HMAC_CONTEXT: &str = "apate-hmac-v1";
pub const RNG_CONTEXT: &str = "apate-rng-v1";
pub const AES_CONTEXT: &str = "apate-aes-v1";
pub const XOR_CONTEXT: &str = "apate-xor-v1";

/// Generate a new 256-bit (32-byte) random key.
pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

/// Load a 32-byte key from a file.
pub fn load_key(path: &Path) -> Result<[u8; 32]> {
    if !path.exists() {
        return Err(ApateError::KeyNotFound(path.to_path_buf()));
    }
    let data = std::fs::read(path)?;
    if data.len() != 32 {
        return Err(ApateError::InvalidKeyLength(data.len()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&data);
    Ok(key)
}

/// Save a 32-byte key to a file.
pub fn save_key(key: &[u8; 32], path: &Path) -> Result<()> {
    std::fs::write(path, key)?;
    Ok(())
}

/// Derive a sub-key from the master key using BLAKE3's key derivation.
///
/// Each `context` string produces a different, independent sub-key.
pub fn derive_subkey(master: &[u8; 32], context: &str) -> [u8; 32] {
    blake3::derive_key(context, master)
}
