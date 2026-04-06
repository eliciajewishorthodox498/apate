# Changelog

## [0.1.1] — 2026-04-06

### Fixed
- **Cross-file rename on Windows** — RA byte offsets were CRLF-based but SemanticRenamer used LF-normalized offsets, causing all cross-file identifier references to silently miss. Self-hosting now compiles at all 3 levels.
- **String pass memory leak** — replaced `Box::leak` + `from_utf8_unchecked` with `std::sync::LazyLock`. Obfuscated strings now decode once and cache, no unsafe code in generated output.
- **Dead code warnings** — removed unused `local_trait_names` field and `is_local_trait` methods from rename pass.

### Changed
- Added `rust-toolchain.toml` and `rustfmt.toml` to pin toolchain (1.91.1) and formatter (edition 2024) across contributors.
- Removed `docs/development/INDEX.md` from git tracking.

## [0.1.0] — 2026-03-24

Initial release. The goddess awakens.

### Added
- 7 obfuscation passes: strip, rename, homoglyph, logic, dead code, strings, reorder
- 3 severity levels: Mild, Spicy, Diabolical
- Keyed deterministic transforms — same key + same input = same output
- AES-256-GCM encrypted manifest for perfect reversal
- Multi-file crate support with cross-file identifier consistency
- Semantic rename engine — rust-analyzer integration for precise local-only identifier renaming
- `SemanticAnalyzer` with panic-safe fallback to heuristic rename
- `--preserve-public` flag for library crates
- `verify` command with CI-friendly exit codes
- CLI with ASCII art banner
- All 3 obfuscation levels self-host (Apate obfuscates itself, output compiles)
- 32 integration tests
