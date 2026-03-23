use std::path::Path;

use apate::key;
use apate::manifest;
use apate::passes::{self, ObfuscationLevel};
use apate::pipeline::Pipeline;
use tempfile::TempDir;

/// Helper: encrypt a file, verify the obfuscated output parses, decrypt, compare to original.
///
/// When strip is included, expects byte-for-byte roundtrip (strip stores original source).
/// Without strip, compares prettyplease-formatted versions (prettyplease reformats code).
fn roundtrip_test(fixture: &Path, pass_names: Vec<String>) {
    let has_strip = pass_names.iter().any(|p| p == "strip");
    let tmp = TempDir::new().unwrap();
    let key = key::generate_key();

    let obfuscated_path = tmp.path().join("obfuscated.rs");
    let manifest_path = tmp.path().join("obfuscated.apate");
    let restored_path = tmp.path().join("restored.rs");

    // Encrypt
    let mut pipeline = Pipeline::new(key, pass_names);
    let m = pipeline.encrypt_single(fixture, &obfuscated_path).unwrap();

    // Verify obfuscated output parses as valid Rust
    let obfuscated_source = std::fs::read_to_string(&obfuscated_path).unwrap();
    syn::parse_file(&obfuscated_source)
        .expect("obfuscated output must be valid Rust syntax");

    // Save manifest
    let encrypted_manifest = manifest::encrypt_manifest(&m, &key).unwrap();
    manifest::save_manifest(&encrypted_manifest, &manifest_path).unwrap();

    // Decrypt
    let decrypt_pipeline = Pipeline::new(key, Vec::new());
    decrypt_pipeline
        .decrypt_single(&obfuscated_path, &restored_path, &manifest_path)
        .unwrap();

    let original = std::fs::read_to_string(fixture).unwrap();
    let restored = std::fs::read_to_string(&restored_path).unwrap();

    if has_strip {
        // Byte-for-byte roundtrip — strip stores the original source
        assert_eq!(
            original, restored,
            "roundtrip failed: restored output differs from original"
        );
    } else {
        // Without strip, prettyplease reformats — compare AST-normalized versions
        let original_normalized = normalize(&original);
        let restored_normalized = normalize(&restored);
        assert_eq!(
            original_normalized, restored_normalized,
            "roundtrip failed: AST structure differs after normalize"
        );
    }
}

/// Normalize source via parse + prettyplease for comparison when strip isn't used.
fn normalize(source: &str) -> String {
    let ast = syn::parse_file(source).expect("source must parse");
    prettyplease::unparse(&ast)
}

fn level1_passes() -> Vec<String> {
    passes::passes_for_level(ObfuscationLevel::Mild)
        .into_iter()
        .map(String::from)
        .collect()
}

// --- Level 1 roundtrip tests ---

#[test]
fn roundtrip_simple_level1() {
    roundtrip_test(Path::new("tests/fixtures/simple.rs"), level1_passes());
}

#[test]
fn roundtrip_structs_level1() {
    roundtrip_test(Path::new("tests/fixtures/structs.rs"), level1_passes());
}

// --- Individual pass roundtrip tests ---

#[test]
fn roundtrip_simple_strip_only() {
    roundtrip_test(
        Path::new("tests/fixtures/simple.rs"),
        vec!["strip".to_string()],
    );
}

#[test]
fn roundtrip_simple_rename_only() {
    roundtrip_test(
        Path::new("tests/fixtures/simple.rs"),
        vec!["rename".to_string()],
    );
}

#[test]
fn roundtrip_simple_reorder_only() {
    roundtrip_test(
        Path::new("tests/fixtures/simple.rs"),
        vec!["reorder".to_string()],
    );
}

#[test]
fn roundtrip_structs_strip_only() {
    roundtrip_test(
        Path::new("tests/fixtures/structs.rs"),
        vec!["strip".to_string()],
    );
}

#[test]
fn roundtrip_structs_rename_only() {
    roundtrip_test(
        Path::new("tests/fixtures/structs.rs"),
        vec!["rename".to_string()],
    );
}

#[test]
fn roundtrip_structs_reorder_only() {
    roundtrip_test(
        Path::new("tests/fixtures/structs.rs"),
        vec!["reorder".to_string()],
    );
}

// --- Phase 3: Homoglyph + String pass tests ---

#[test]
fn roundtrip_simple_homoglyph_only() {
    roundtrip_test(
        Path::new("tests/fixtures/simple.rs"),
        vec!["homoglyph".to_string()],
    );
}

#[test]
fn roundtrip_structs_homoglyph_only() {
    roundtrip_test(
        Path::new("tests/fixtures/structs.rs"),
        vec!["homoglyph".to_string()],
    );
}

#[test]
fn roundtrip_simple_strings_only() {
    roundtrip_test(
        Path::new("tests/fixtures/simple.rs"),
        vec!["strings".to_string()],
    );
}

#[test]
fn roundtrip_structs_strings_only() {
    roundtrip_test(
        Path::new("tests/fixtures/structs.rs"),
        vec!["strings".to_string()],
    );
}

#[test]
fn roundtrip_simple_strip_rename_homoglyph() {
    roundtrip_test(
        Path::new("tests/fixtures/simple.rs"),
        vec![
            "strip".to_string(),
            "rename".to_string(),
            "homoglyph".to_string(),
            "reorder".to_string(),
        ],
    );
}

#[test]
fn roundtrip_simple_all_phase3() {
    roundtrip_test(
        Path::new("tests/fixtures/simple.rs"),
        vec![
            "strip".to_string(),
            "rename".to_string(),
            "homoglyph".to_string(),
            "strings".to_string(),
            "reorder".to_string(),
        ],
    );
}

// --- Phase 4: Logic + Dead Code pass tests ---

fn level2_passes() -> Vec<String> {
    passes::passes_for_level(ObfuscationLevel::Spicy)
        .into_iter()
        .map(String::from)
        .collect()
}

fn level3_passes() -> Vec<String> {
    passes::passes_for_level(ObfuscationLevel::Diabolical)
        .into_iter()
        .map(String::from)
        .collect()
}

#[test]
fn roundtrip_simple_logic_only() {
    roundtrip_test(
        Path::new("tests/fixtures/simple.rs"),
        vec!["logic".to_string()],
    );
}

#[test]
fn roundtrip_simple_dead_code_only() {
    roundtrip_test(
        Path::new("tests/fixtures/simple.rs"),
        vec!["dead_code".to_string()],
    );
}

#[test]
fn roundtrip_simple_level2() {
    roundtrip_test(Path::new("tests/fixtures/simple.rs"), level2_passes());
}

#[test]
fn roundtrip_simple_level3() {
    roundtrip_test(Path::new("tests/fixtures/simple.rs"), level3_passes());
}

#[test]
fn roundtrip_structs_level3() {
    roundtrip_test(Path::new("tests/fixtures/structs.rs"), level3_passes());
}

#[test]
fn roundtrip_complex_level1() {
    roundtrip_test(Path::new("tests/fixtures/complex.rs"), level1_passes());
}

#[test]
fn roundtrip_complex_level3() {
    roundtrip_test(Path::new("tests/fixtures/complex.rs"), level3_passes());
}

// --- Phase 5: Multi-file + preserve-public tests ---

/// Helper for multi-file roundtrip: encrypt dir, decrypt dir, compare all files.
fn roundtrip_crate_test(fixture_dir: &Path, pass_names: Vec<String>) {
    let tmp = TempDir::new().unwrap();
    let key = key::generate_key();

    let obfuscated_dir = tmp.path().join("obfuscated");
    let manifest_path = obfuscated_dir.join("manifest.apate");
    let restored_dir = tmp.path().join("restored");

    let mut pipeline = Pipeline::new(key, pass_names);
    let m = pipeline.encrypt_crate(fixture_dir, &obfuscated_dir).unwrap();

    let encrypted_manifest = manifest::encrypt_manifest(&m, &key).unwrap();
    manifest::save_manifest(&encrypted_manifest, &manifest_path).unwrap();

    let decrypt_pipeline = Pipeline::new(key, Vec::new());
    let encrypted = manifest::load_manifest(&manifest_path).unwrap();
    let manifest = manifest::decrypt_manifest(&encrypted, &key).unwrap();
    decrypt_pipeline
        .decrypt_crate(&obfuscated_dir, &restored_dir, &manifest)
        .unwrap();

    // Compare each file
    for file_manifest in &m.files {
        let original = std::fs::read_to_string(fixture_dir.join(&file_manifest.relative_path))
            .unwrap();
        let restored = std::fs::read_to_string(restored_dir.join(&file_manifest.relative_path))
            .unwrap();
        assert_eq!(
            original, restored,
            "roundtrip failed for {:?}",
            file_manifest.relative_path
        );
    }
}

#[test]
fn roundtrip_multifile_level1() {
    roundtrip_crate_test(Path::new("tests/fixtures/multifile"), level1_passes());
}

#[test]
fn roundtrip_multifile_level3() {
    roundtrip_crate_test(Path::new("tests/fixtures/multifile"), level3_passes());
}

#[test]
fn roundtrip_preserve_public() {
    let fixture = Path::new("tests/fixtures/multifile/utils.rs");
    let tmp = TempDir::new().unwrap();
    let key = key::generate_key();

    let obfuscated = tmp.path().join("obfuscated.rs");

    let mut pipeline = Pipeline::new(key, level1_passes());
    pipeline.preserve_public = true;
    let m = pipeline.encrypt_single(fixture, &obfuscated).unwrap();

    let output = std::fs::read_to_string(&obfuscated).unwrap();

    // Bare pub items should keep their names
    assert!(output.contains("fn process"), "pub fn process should be preserved");
    assert!(output.contains("fn helper"), "pub fn helper should be preserved");

    // Non-pub items should be renamed
    assert!(!output.contains("internal_detail"), "non-pub fn should be renamed");

    // Still roundtrips
    let manifest_path = tmp.path().join("obfuscated.apate");
    let encrypted = manifest::encrypt_manifest(&m, &key).unwrap();
    manifest::save_manifest(&encrypted, &manifest_path).unwrap();

    let restored = tmp.path().join("restored.rs");
    let decrypt_pipeline = Pipeline::new(key, Vec::new());
    decrypt_pipeline.decrypt_single(&obfuscated, &restored, &manifest_path).unwrap();

    let original = std::fs::read_to_string(fixture).unwrap();
    let restored_text = std::fs::read_to_string(&restored).unwrap();
    assert_eq!(original, restored_text, "preserve-public roundtrip failed");
}
