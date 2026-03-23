use std::path::Path;

use apate::key;
use apate::passes::{self, ObfuscationLevel};
use apate::pipeline::Pipeline;
use tempfile::TempDir;

fn level1_passes() -> Vec<String> {
    passes::passes_for_level(ObfuscationLevel::Mild)
        .into_iter()
        .map(String::from)
        .collect()
}

#[test]
fn same_key_produces_identical_output() {
    let fixture = Path::new("tests/fixtures/simple.rs");
    let tmp = TempDir::new().unwrap();
    let key = key::generate_key();

    let out1 = tmp.path().join("out1.rs");
    let out2 = tmp.path().join("out2.rs");

    let mut pipeline1 = Pipeline::new(key, level1_passes());
    pipeline1.encrypt_single(fixture, &out1).unwrap();

    let mut pipeline2 = Pipeline::new(key, level1_passes());
    pipeline2.encrypt_single(fixture, &out2).unwrap();

    let content1 = std::fs::read_to_string(&out1).unwrap();
    let content2 = std::fs::read_to_string(&out2).unwrap();

    assert_eq!(
        content1, content2,
        "same key must produce identical obfuscated output"
    );
}

#[test]
fn different_key_produces_different_output() {
    let fixture = Path::new("tests/fixtures/simple.rs");
    let tmp = TempDir::new().unwrap();

    let key1 = key::generate_key();
    let key2 = key::generate_key();

    let out1 = tmp.path().join("out1.rs");
    let out2 = tmp.path().join("out2.rs");

    let mut pipeline1 = Pipeline::new(key1, level1_passes());
    pipeline1.encrypt_single(fixture, &out1).unwrap();

    let mut pipeline2 = Pipeline::new(key2, level1_passes());
    pipeline2.encrypt_single(fixture, &out2).unwrap();

    let content1 = std::fs::read_to_string(&out1).unwrap();
    let content2 = std::fs::read_to_string(&out2).unwrap();

    assert_ne!(
        content1, content2,
        "different keys must produce different obfuscated output"
    );
}

#[test]
fn determinism_with_structs_fixture() {
    let fixture = Path::new("tests/fixtures/structs.rs");
    let tmp = TempDir::new().unwrap();
    let key = key::generate_key();

    let out1 = tmp.path().join("out1.rs");
    let out2 = tmp.path().join("out2.rs");

    let mut pipeline1 = Pipeline::new(key, level1_passes());
    pipeline1.encrypt_single(fixture, &out1).unwrap();

    let mut pipeline2 = Pipeline::new(key, level1_passes());
    pipeline2.encrypt_single(fixture, &out2).unwrap();

    let content1 = std::fs::read_to_string(&out1).unwrap();
    let content2 = std::fs::read_to_string(&out2).unwrap();

    assert_eq!(
        content1, content2,
        "same key must produce identical output for structs fixture"
    );
}

#[test]
fn determinism_homoglyph() {
    let fixture = Path::new("tests/fixtures/simple.rs");
    let tmp = TempDir::new().unwrap();
    let key = key::generate_key();

    let out1 = tmp.path().join("out1.rs");
    let out2 = tmp.path().join("out2.rs");

    let passes = vec!["homoglyph".to_string()];

    Pipeline::new(key, passes.clone())
        .encrypt_single(fixture, &out1)
        .unwrap();
    Pipeline::new(key, passes)
        .encrypt_single(fixture, &out2)
        .unwrap();

    let content1 = std::fs::read_to_string(&out1).unwrap();
    let content2 = std::fs::read_to_string(&out2).unwrap();

    assert_eq!(
        content1, content2,
        "same key must produce identical homoglyph output"
    );
}

#[test]
fn determinism_strings() {
    let fixture = Path::new("tests/fixtures/simple.rs");
    let tmp = TempDir::new().unwrap();
    let key = key::generate_key();

    let out1 = tmp.path().join("out1.rs");
    let out2 = tmp.path().join("out2.rs");

    let passes = vec!["strings".to_string()];

    Pipeline::new(key, passes.clone())
        .encrypt_single(fixture, &out1)
        .unwrap();
    Pipeline::new(key, passes)
        .encrypt_single(fixture, &out2)
        .unwrap();

    let content1 = std::fs::read_to_string(&out1).unwrap();
    let content2 = std::fs::read_to_string(&out2).unwrap();

    assert_eq!(
        content1, content2,
        "same key must produce identical string-encoded output"
    );
}

#[test]
fn determinism_logic() {
    let fixture = Path::new("tests/fixtures/simple.rs");
    let tmp = TempDir::new().unwrap();
    let key = key::generate_key();
    let passes = vec!["logic".to_string()];

    let out1 = tmp.path().join("out1.rs");
    let out2 = tmp.path().join("out2.rs");

    Pipeline::new(key, passes.clone()).encrypt_single(fixture, &out1).unwrap();
    Pipeline::new(key, passes.clone()).encrypt_single(fixture, &out2).unwrap();

    let content1 = std::fs::read_to_string(&out1).unwrap();
    let content2 = std::fs::read_to_string(&out2).unwrap();
    assert_eq!(content1, content2, "same key must produce identical logic output");
}

#[test]
fn determinism_dead_code() {
    let fixture = Path::new("tests/fixtures/simple.rs");
    let tmp = TempDir::new().unwrap();
    let key = key::generate_key();
    let passes = vec!["dead_code".to_string()];

    let out1 = tmp.path().join("out1.rs");
    let out2 = tmp.path().join("out2.rs");

    Pipeline::new(key, passes.clone()).encrypt_single(fixture, &out1).unwrap();
    Pipeline::new(key, passes.clone()).encrypt_single(fixture, &out2).unwrap();

    let content1 = std::fs::read_to_string(&out1).unwrap();
    let content2 = std::fs::read_to_string(&out2).unwrap();
    assert_eq!(content1, content2, "same key must produce identical dead code output");
}

#[test]
fn determinism_level3() {
    let fixture = Path::new("tests/fixtures/simple.rs");
    let tmp = TempDir::new().unwrap();
    let key = key::generate_key();
    let passes: Vec<String> = passes::passes_for_level(passes::ObfuscationLevel::Diabolical)
        .into_iter().map(String::from).collect();

    let out1 = tmp.path().join("out1.rs");
    let out2 = tmp.path().join("out2.rs");

    Pipeline::new(key, passes.clone()).encrypt_single(fixture, &out1).unwrap();
    Pipeline::new(key, passes.clone()).encrypt_single(fixture, &out2).unwrap();

    let content1 = std::fs::read_to_string(&out1).unwrap();
    let content2 = std::fs::read_to_string(&out2).unwrap();
    assert_eq!(content1, content2, "same key must produce identical Level 3 output");
}
