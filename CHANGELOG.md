# Changelog

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
