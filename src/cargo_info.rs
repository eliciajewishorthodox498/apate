use std::collections::HashSet;
use std::path::Path;

use crate::error::Result;

/// Crate metadata parsed from Cargo.toml — used to distinguish internal vs external paths.
#[derive(Debug, Clone)]
pub struct CrateInfo {
    /// The crate's own name from [package].name, with hyphens normalized to underscores.
    pub crate_name: String,
    /// Set of external dependency crate names (normalized: hyphens → underscores).
    pub external_crates: HashSet<String>,
}

/// Parse a Cargo.toml to extract the crate name and external dependency names.
///
/// If the Cargo.toml is a virtual workspace manifest (no [package] section),
/// returns a default CrateInfo with an empty crate name.
pub fn parse_cargo_toml(crate_dir: &Path) -> Result<CrateInfo> {
    let cargo_path = crate_dir.join("Cargo.toml");
    let content = std::fs::read_to_string(&cargo_path)?;
    let table: toml::Table = content
        .parse()
        .map_err(|e| crate::error::ApateError::PassFailed {
            pass: "cargo_info".into(),
            reason: format!("failed to parse Cargo.toml: {e}"),
        })?;

    let crate_name = table
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .replace('-', "_");

    let mut external_crates = HashSet::new();
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(deps) = table.get(section).and_then(|d| d.as_table()) {
            for key in deps.keys() {
                external_crates.insert(key.replace('-', "_"));
            }
        }
    }

    Ok(CrateInfo {
        crate_name,
        external_crates,
    })
}

/// Try to find and parse Cargo.toml by walking up from a file path.
pub fn find_cargo_toml(start: &Path) -> Option<CrateInfo> {
    let mut dir = if start.is_file() {
        start.parent()?
    } else {
        start
    };

    loop {
        if dir.join("Cargo.toml").exists() {
            return parse_cargo_toml(dir).ok();
        }
        dir = dir.parent()?;
    }
}
