use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

pub mod dead_code;
pub mod homoglyph;
pub mod logic;
pub mod rename;
pub mod reorder;
pub mod strings;
pub mod strip;

use crate::cargo_info::CrateInfo;
use crate::error::Result;
use crate::semantic::LocalDefMap;
use crate::key;
use crate::utils::crypto;

/// Every obfuscation pass implements this trait.
pub trait ObfuscationPass {
    /// Unique identifier for this pass (used in manifest).
    fn name(&self) -> &'static str;

    /// Apply the obfuscation transform.
    ///
    /// Returns a record of what was done so the transform can be reversed.
    fn encrypt(
        &self,
        ast: &mut syn::File,
        context: &mut PassContext,
    ) -> Result<PassRecord>;

    /// Reverse the obfuscation using the stored record.
    fn decrypt(
        &self,
        ast: &mut syn::File,
        record: &PassRecord,
        context: &PassContext,
    ) -> Result<()>;
}

/// Shared state carried across passes during a single file's processing.
pub struct PassContext {
    /// Keyed PRNG — all randomness derives from this.
    pub rng: ChaCha20Rng,
    /// HMAC key derived from the master key (for deterministic renaming).
    pub hmac_key: Vec<u8>,
    /// Current file path (for multi-file operations).
    pub current_file: PathBuf,
    /// Global identifier registry (tracks renames across files for consistency).
    pub ident_registry: HashMap<String, String>,
    /// Cross-file export registry — only item-level definitions (types, functions,
    /// constants, struct fields, enum variants) from the pre-pass. Used for
    /// multi-segment path and field access lookups without polluting local mappings.
    pub cross_file_exports: HashMap<String, String>,
    /// XOR key derived from the master key (for string encoding).
    pub xor_key: Vec<u8>,
    /// When true, skip renaming/homoglyphing bare `pub` items (external API boundary).
    pub preserve_public: bool,
    /// Crate metadata from Cargo.toml — used to distinguish internal vs external paths.
    pub crate_info: Option<CrateInfo>,
    /// RA semantic analysis — maps (file, byte_range) to local identifier names.
    /// When present, the rename pass uses this instead of heuristic-based collection.
    pub local_def_map: Option<Arc<LocalDefMap>>,
    /// Original source text before any transforms — set by the pipeline,
    /// used by the strip pass to store for roundtrip restoration.
    pub original_source: Option<String>,
    /// Relative file path (relative to crate root) for LocalDefMap queries.
    /// Set by the pipeline when processing multi-file crates.
    pub relative_file: Option<PathBuf>,
}

impl PassContext {
    /// Create a new context for processing a single file.
    ///
    /// Derives sub-keys and seeds the RNG from the master key + file path.
    pub fn new(master_key: &[u8; 32], file_path: &Path) -> Self {
        let hmac_subkey = key::derive_subkey(master_key, key::HMAC_CONTEXT);
        let xor_subkey = key::derive_subkey(master_key, key::XOR_CONTEXT);
        Self {
            rng: crypto::seed_rng(master_key, file_path),
            hmac_key: hmac_subkey.to_vec(),
            current_file: file_path.to_path_buf(),
            ident_registry: HashMap::new(),
            cross_file_exports: HashMap::new(),
            xor_key: xor_subkey.to_vec(),
            preserve_public: false,
            crate_info: None,
            local_def_map: None,
            original_source: None,
            relative_file: None,
        }
    }
}

/// A record of what a single pass did — stored in the manifest for reversal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassRecord {
    pub pass_name: String,
    pub data: serde_json::Value,
}

/// Obfuscation severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObfuscationLevel {
    /// Strip + Rename + Reorder — readable if you squint.
    Mild,
    /// Level 1 + Homoglyph + Logic + Strings — actively hostile.
    Spicy,
    /// All passes including dead code injection — good luck.
    Diabolical,
}

impl ObfuscationLevel {
    /// Parse a level from a 1-3 integer.
    pub fn from_u8(n: u8) -> Option<Self> {
        match n {
            1 => Some(Self::Mild),
            2 => Some(Self::Spicy),
            3 => Some(Self::Diabolical),
            _ => None,
        }
    }
}

/// Returns the ordered pass names for a given obfuscation level.
pub fn passes_for_level(level: ObfuscationLevel) -> Vec<&'static str> {
    match level {
        ObfuscationLevel::Mild => vec!["strip", "rename", "reorder"],
        ObfuscationLevel::Spicy => vec![
            "strip", "rename", "homoglyph", "logic", "strings", "reorder",
        ],
        ObfuscationLevel::Diabolical => vec![
            "strip", "rename", "homoglyph", "logic", "dead_code", "strings", "reorder",
        ],
    }
}

/// Resolve which passes to run.
///
/// Explicit pass list takes priority over level. Defaults to Level 1 if neither given.
pub fn resolve_passes(
    level: Option<ObfuscationLevel>,
    explicit: Option<&[String]>,
) -> Vec<String> {
    if let Some(passes) = explicit {
        return passes.to_vec();
    }
    let level = level.unwrap_or(ObfuscationLevel::Mild);
    passes_for_level(level)
        .into_iter()
        .map(String::from)
        .collect()
}
