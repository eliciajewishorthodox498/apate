use std::path::Path;

use hmac::{Hmac, Mac};
use rand_chacha::ChaCha20Rng;
use rand::SeedableRng;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 over `data` with the given `key`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Compute a BLAKE3 hash of `data`.
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Create a deterministic ChaCha20 RNG seeded from `BLAKE3(master_key || file_path)`.
///
/// Each file gets unique but reproducible randomness.
pub fn seed_rng(master_key: &[u8; 32], file_path: &Path) -> ChaCha20Rng {
    let path_bytes = file_path.to_string_lossy().as_bytes().to_vec();
    let mut input = master_key.to_vec();
    input.extend_from_slice(&path_bytes);
    let seed = blake3_hash(&input);
    ChaCha20Rng::from_seed(seed)
}
