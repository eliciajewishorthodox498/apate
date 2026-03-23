use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use indicatif::{ProgressBar, ProgressStyle};
use walkdir::WalkDir;

use std::sync::Arc;

use crate::cargo_info::{self, CrateInfo};
use crate::error::{ApateError, Result};
use crate::semantic::{LocalDefMap, SemanticAnalyzer};
use crate::manifest::{self, FileManifest, Manifest};
use crate::passes::{ObfuscationLevel, PassContext};
use crate::utils::{ast, crypto};

/// Orchestrates the obfuscation/deobfuscation pipeline.
pub struct Pipeline {
    master_key: [u8; 32],
    pass_names: Vec<String>,
    pub preserve_public: bool,
    crate_info: Option<CrateInfo>,
    local_def_map: Option<Arc<LocalDefMap>>,
    /// Crate root directory (where Cargo.toml lives) — used to compute
    /// relative file paths for LocalDefMap queries.
    crate_root: Option<PathBuf>,
}

impl Pipeline {
    /// Create a pipeline with an explicit list of pass names.
    pub fn new(master_key: [u8; 32], pass_names: Vec<String>) -> Self {
        Self {
            master_key,
            pass_names,
            preserve_public: false,
            crate_info: None,
            local_def_map: None,
            crate_root: None,
        }
    }

    /// Create a pipeline from an obfuscation level.
    pub fn from_level(master_key: [u8; 32], level: ObfuscationLevel) -> Self {
        let pass_names = crate::passes::passes_for_level(level)
            .into_iter()
            .map(String::from)
            .collect();
        Self {
            master_key,
            pass_names,
            preserve_public: false,
            crate_info: None,
            local_def_map: None,
            crate_root: None,
        }
    }

    /// Encrypt a single source file.
    ///
    /// Optionally accepts a pre-populated `ident_registry` for multi-file mode.
    /// Returns the `FileManifest` and the updated `ident_registry`.
    pub fn encrypt_file(
        &self,
        input: &Path,
        output: &Path,
        shared_registry: Option<&HashMap<String, String>>,
        cross_file_exports: Option<&HashMap<String, String>>,
    ) -> Result<(FileManifest, HashMap<String, String>)> {
        let source = std::fs::read_to_string(input)?;
        let hash_bytes = crypto::blake3_hash(source.as_bytes());
        let original_hash = hash_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        let mut file_ast = syn::parse_file(&source).map_err(|e| ApateError::ParseError {
            path: input.to_path_buf(),
            source: e,
        })?;

        let mut context = PassContext::new(&self.master_key, input);
        context.original_source = Some(source.clone());
        context.preserve_public = self.preserve_public;
        context.crate_info = self.crate_info.clone();

        // Inject shared ident_registry from previous files (multi-file mode)
        if let Some(registry) = shared_registry {
            context.ident_registry = registry.clone();
        }
        if let Some(exports) = cross_file_exports {
            context.cross_file_exports = exports.clone();
        }
        context.local_def_map = self.local_def_map.clone();

        // Compute relative file path for LocalDefMap queries
        if let Some(ref root) = self.crate_root {
            if let Ok(rel) = input.strip_prefix(root) {
                context.relative_file = Some(rel.to_path_buf());
            }
        }

        let mut records = Vec::new();

        for pass_name in &self.pass_names {
            if let Some(pass) = get_pass(pass_name) {
                let record = pass.encrypt(&mut file_ast, &mut context)?;
                records.push(record);
            } else {
                eprintln!("  [skip] pass '{}' not yet implemented", pass_name);
            }
        }

        let transformed = ast::file_to_source(&file_ast);
        std::fs::write(output, &transformed)?;

        let file_manifest = FileManifest {
            relative_path: input.to_path_buf(),
            original_hash,
            passes: records,
        };

        Ok((file_manifest, context.ident_registry))
    }

    /// Decrypt a single obfuscated file using its manifest.
    ///
    /// Optionally accepts a combined rename mapping for cross-file references.
    pub fn decrypt_file(
        &self,
        input: &Path,
        output: &Path,
        file_manifest: &FileManifest,
        _combined_rename_map: Option<&HashMap<String, String>>,
    ) -> Result<()> {
        let source = std::fs::read_to_string(input)?;

        let mut file_ast = syn::parse_file(&source).map_err(|e| ApateError::ParseError {
            path: input.to_path_buf(),
            source: e,
        })?;

        let context = PassContext::new(&self.master_key, &file_manifest.relative_path);

        // Reverse the passes in opposite order
        for record in file_manifest.passes.iter().rev() {
            if let Some(pass) = get_pass(&record.pass_name) {
                pass.decrypt(&mut file_ast, record, &context)?;
            } else {
                eprintln!(
                    "  [skip] pass '{}' not available for decryption",
                    record.pass_name
                );
            }
        }

        // If strip pass was involved, restore the original source text
        // for byte-for-byte roundtrip (prettyplease reformats, so we can't use it).
        let restored = if let Some(strip_record) =
            file_manifest.passes.iter().find(|r| r.pass_name == "strip")
        {
            crate::passes::strip::extract_original_source(strip_record)?
        } else {
            ast::file_to_source(&file_ast)
        };
        std::fs::write(output, &restored)?;

        Ok(())
    }

    /// Encrypt a single file and produce a complete manifest.
    pub fn encrypt_single(&mut self, input: &Path, output: &Path) -> Result<Manifest> {
        // Try to find Cargo.toml for crate info if not already set
        if self.crate_info.is_none() {
            self.crate_info = cargo_info::find_cargo_toml(input);
        }
        // Try RA analysis for single-file mode (only if inside a Cargo project)
        if self.local_def_map.is_none() && self.pass_names.iter().any(|p| p == "rename") {
            if let Some(root) = find_crate_root(input) {
                self.crate_root = Some(root.clone());
                match SemanticAnalyzer::load(&root) {
                    Ok(analyzer) => {
                        if let Ok(map) = analyzer.build_local_def_map() {
                            self.local_def_map = Some(Arc::new(map));
                        }
                    }
                    Err(_) => {} // Graceful fallback to heuristics
                }
            }
        }
        let (file_manifest, _registry) = self.encrypt_file(input, output, None, None)?;
        let mut m = Manifest::new();
        m.files.push(file_manifest);
        Ok(m)
    }

    /// Decrypt a single file using an encrypted manifest file.
    pub fn decrypt_single(
        &self,
        input: &Path,
        output: &Path,
        manifest_path: &Path,
    ) -> Result<()> {
        let encrypted = manifest::load_manifest(manifest_path)?;
        let m = manifest::decrypt_manifest(&encrypted, &self.master_key)?;

        let file_manifest = m.files.first().ok_or_else(|| ApateError::PassFailed {
            pass: "pipeline".into(),
            reason: "manifest contains no file entries".into(),
        })?;

        self.decrypt_file(input, output, file_manifest, None)
    }

    /// Encrypt an entire crate directory.
    ///
    /// Walks all `.rs` files in sorted order, sharing the `ident_registry`
    /// across files so cross-file identifier references stay consistent.
    pub fn encrypt_crate(&mut self, input_dir: &Path, output_dir: &Path) -> Result<Manifest> {
        let rs_files = collect_rs_files(input_dir)?;
        std::fs::create_dir_all(output_dir)?;

        // Parse Cargo.toml for crate info
        if self.crate_info.is_none() {
            self.crate_info = cargo_info::parse_cargo_toml(input_dir).ok();
        }

        self.crate_root = Some(input_dir.to_path_buf());

        // Run RA semantic analysis if rename pass is enabled and Cargo.toml exists
        if self.local_def_map.is_none()
            && self.pass_names.iter().any(|p| p == "rename")
            && input_dir.join("Cargo.toml").exists()
        {
            let spinner = ProgressBar::new_spinner();
            spinner.set_style(
                ProgressStyle::default_spinner()
                    .template("  {spinner:.magenta} Analyzing workspace... ({elapsed})")
                    .unwrap(),
            );
            spinner.enable_steady_tick(std::time::Duration::from_millis(80));
            let start = Instant::now();

            // Catch panics from RA (salsa DB threading issues, etc.)
            let dir = input_dir.to_path_buf();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let analyzer = SemanticAnalyzer::load(&dir)?;
                analyzer.build_local_def_map()
            }));

            spinner.finish_and_clear();
            let elapsed = start.elapsed();

            match result {
                Ok(Ok(map)) => {
                    eprintln!(
                        "  \x1b[35m✓\x1b[0m Semantic analysis: {} local references mapped ({:.1}s)",
                        map.len(),
                        elapsed.as_secs_f64()
                    );
                    self.local_def_map = Some(Arc::new(map));
                }
                Ok(Err(e)) => {
                    eprintln!("  [warn] RA analysis failed, falling back to heuristics: {e}");
                }
                Err(_) => {
                    eprintln!("  [warn] RA panicked, falling back to heuristics");
                }
            }
        }

        // Copy all non-.rs files through untouched (Cargo.toml, Cargo.lock, build.rs, etc.)
        copy_non_rs_files(input_dir, output_dir)?;

        // PASS 1: Pre-collect item-level definitions (types, functions, constants,
        // struct fields, enum variants) across ALL files. This builds the cross-file
        // export registry so field access and module-prefixed paths resolve correctly.
        let mut cross_file_exports: HashMap<String, String> = HashMap::new();
        if self.pass_names.contains(&"rename".to_string()) {
            for rel_path in &rs_files {
                let input_path = input_dir.join(rel_path);
                let source = std::fs::read_to_string(&input_path)?;
                let file_ast = syn::parse_file(&source).map_err(|e| ApateError::ParseError {
                    path: input_path.clone(),
                    source: e,
                })?;
                crate::passes::rename::collect_file_definitions(
                    &file_ast,
                    &self.master_key,
                    &mut cross_file_exports,
                    self.crate_info.as_ref(),
                    self.preserve_public,
                );
            }
        }

        // PASS 2: Actually encrypt each file.
        // Seed the ident_registry with the pre-pass exports so each file
        // sees all cross-file definitions from the start.
        let mut shared_registry = cross_file_exports.clone();
        let mut manifest = Manifest::new();

        let progress = ProgressBar::new(rs_files.len() as u64);
        progress.set_style(
            ProgressStyle::default_bar()
                .template("  {prefix} [{bar:30.magenta/white}] {pos}/{len} files")
                .unwrap()
                .progress_chars("█▓░"),
        );
        progress.set_prefix("Encrypting");

        for rel_path in &rs_files {
            let input_path = input_dir.join(rel_path);
            let output_path = output_dir.join(rel_path);

            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let (mut file_manifest, updated_registry) =
                self.encrypt_file(&input_path, &output_path, Some(&shared_registry), Some(&cross_file_exports))?;

            file_manifest.relative_path = rel_path.clone();
            shared_registry = updated_registry;
            manifest.files.push(file_manifest);
            progress.inc(1);
        }
        progress.finish_and_clear();
        eprintln!(
            "  \x1b[35m✓\x1b[0m Encrypted {} files",
            rs_files.len()
        );

        Ok(manifest)
    }

    /// Decrypt an entire crate directory using its manifest.
    ///
    /// Builds a combined rename mapping from all files before processing,
    /// so cross-file identifier references resolve correctly.
    pub fn decrypt_crate(
        &self,
        input_dir: &Path,
        output_dir: &Path,
        manifest: &Manifest,
    ) -> Result<()> {
        std::fs::create_dir_all(output_dir)?;

        // Build combined reverse rename mapping from ALL files first
        let combined_map = build_combined_rename_map(manifest);

        for file_manifest in &manifest.files {
            let input_path = input_dir.join(&file_manifest.relative_path);
            let output_path = output_dir.join(&file_manifest.relative_path);

            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            self.decrypt_file(&input_path, &output_path, file_manifest, Some(&combined_map))?;
        }

        Ok(())
    }

    /// Verify that obfuscated source roundtrips to the original.
    pub fn verify_file(
        &self,
        original: &Path,
        obfuscated: &Path,
        manifest_path: &Path,
    ) -> Result<bool> {
        let temp = tempfile::NamedTempFile::new()?;
        let temp_path = temp.path().to_path_buf();

        self.decrypt_single(obfuscated, &temp_path, manifest_path)?;

        let original_hash = crypto::blake3_hash(&std::fs::read(original)?);
        let decrypted_hash = crypto::blake3_hash(&std::fs::read(&temp_path)?);

        Ok(original_hash == decrypted_hash)
    }

    /// Verify that an obfuscated crate roundtrips to the original.
    pub fn verify_crate(
        &self,
        original_dir: &Path,
        obfuscated_dir: &Path,
        manifest_path: &Path,
    ) -> Result<Vec<(PathBuf, bool)>> {
        let encrypted = manifest::load_manifest(manifest_path)?;
        let m = manifest::decrypt_manifest(&encrypted, &self.master_key)?;

        let temp_dir = tempfile::TempDir::new()?;
        self.decrypt_crate(obfuscated_dir, temp_dir.path(), &m)?;

        let mut results = Vec::new();
        for file_manifest in &m.files {
            let original_path = original_dir.join(&file_manifest.relative_path);
            let decrypted_path = temp_dir.path().join(&file_manifest.relative_path);

            let original_hash = crypto::blake3_hash(&std::fs::read(&original_path)?);
            let decrypted_hash = crypto::blake3_hash(&std::fs::read(&decrypted_path)?);

            results.push((file_manifest.relative_path.clone(), original_hash == decrypted_hash));
        }

        Ok(results)
    }
}

/// Copy all non-`.rs` files from input to output directory, preserving structure.
///
/// Skips `.git`, `target`, and other build artifact directories.
fn copy_non_rs_files(input_dir: &Path, output_dir: &Path) -> Result<()> {
    for entry in WalkDir::new(input_dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let rel = match entry.path().strip_prefix(input_dir) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Skip directories we never want to copy
        let rel_str = rel.to_string_lossy();
        if rel_str.starts_with(".git")
            || rel_str.starts_with("target")
            || rel_str.starts_with(".apate")
        {
            continue;
        }

        let dest = output_dir.join(rel);

        if entry.file_type().is_dir() {
            std::fs::create_dir_all(&dest)?;
        } else if entry.path().extension().is_none_or(|ext| ext != "rs") {
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(entry.path(), &dest)?;
        }
    }
    Ok(())
}

/// Collect all `.rs` files in a directory, returning sorted relative paths.
fn collect_rs_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            // Skip .git, target, and .apate directories
            let rel = e.path().strip_prefix(dir).unwrap_or(e.path());
            let rel_str = rel.to_string_lossy();
            if rel_str.starts_with(".git")
                || rel_str.starts_with("target")
                || rel_str.starts_with(".apate")
            {
                return false;
            }
            e.path().extension().is_some_and(|ext| ext == "rs")
        })
        .filter_map(|e| e.path().strip_prefix(dir).ok().map(PathBuf::from))
        .collect();
    files.sort();
    Ok(files)
}

/// Build a combined reverse rename mapping (obfuscated → original) from all files.
///
/// This is needed for cross-file decrypt: file A might reference a struct
/// defined in file B, so file A's manifest alone won't have that mapping.
fn build_combined_rename_map(manifest: &Manifest) -> HashMap<String, String> {
    let mut combined = HashMap::new();
    for file_manifest in &manifest.files {
        for record in &file_manifest.passes {
            if record.pass_name == "rename"
                && let Ok(data) = serde_json::from_value::<RenameDataHelper>(record.data.clone())
            {
                for (original, obfuscated) in &data.mapping {
                    combined.insert(obfuscated.clone(), original.clone());
                }
            }
        }
    }
    combined
}

/// Helper struct to deserialize rename pass data for cross-file mapping.
#[derive(serde::Deserialize)]
struct RenameDataHelper {
    mapping: HashMap<String, String>,
}

/// Look up a pass implementation by name.
fn get_pass(name: &str) -> Option<Box<dyn crate::passes::ObfuscationPass>> {
    use crate::passes::{dead_code, homoglyph, logic, rename, reorder, strings, strip};
    match name {
        "strip" => Some(Box::new(strip::StripPass)),
        "rename" => Some(Box::new(rename::RenamePass)),
        "homoglyph" => Some(Box::new(homoglyph::HomoglyphPass)),
        "logic" => Some(Box::new(logic::LogicPass)),
        "dead_code" => Some(Box::new(dead_code::DeadCodePass)),
        "strings" => Some(Box::new(strings::StringPass)),
        "reorder" => Some(Box::new(reorder::ReorderPass)),
        _ => None,
    }
}

/// Walk up from a file to find the nearest directory containing Cargo.toml.
fn find_crate_root(file: &Path) -> Option<PathBuf> {
    let mut dir = file.parent()?;
    loop {
        if dir.join("Cargo.toml").exists() {
            return Some(dir.to_path_buf());
        }
        dir = dir.parent()?;
    }
}
