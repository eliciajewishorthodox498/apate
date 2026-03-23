# Apate Development Index

Master tracking document for the phased implementation of Apate.

Full project spec: [../APATE.md](../APATE.md)

## Phase Overview

| Phase | Name | Status | Description |
|-------|------|--------|-------------|
| 1 | [Foundation](PHASE_1_FOUNDATION.md) | ✅ COMPLETE | Error types, key management, pass trait, pipeline, manifest, CLI skeleton |
| 2 | [Core Passes](PHASE_2_CORE_PASSES.md) | ✅ COMPLETE | Strip, Rename, Reorder — Level 1 obfuscation working end-to-end |
| 3 | [Unicode & Strings](PHASE_3_UNICODE_STRINGS.md) | ✅ COMPLETE | Homoglyph injection + String literal encoding |
| 4 | [Logic & Dead Code](PHASE_4_LOGIC_DEAD_CODE.md) | ✅ COMPLETE | Control-flow transforms + Dead code injection — Levels 2-3 complete |
| 5 | [Polish & Release](PHASE_5_POLISH.md) | ✅ COMPLETE | Multi-file support, verify command, --preserve-public, README |
| 6 | [Rename Hardening](PHASE_6_RENAME_HARDENING.md) | ✅ COMPLETE | Cargo.toml parsing, cross-file exports, format strings, RA integration |
| 6C | [RA Performance](PHASE_6C_RA_PERFORMANCE.md) | ✅ COMPLETE | SemanticRenamer, LocalDefMap, indicatif UX |
| 7 | [CLI Preservation](PHASE_7_CLI_PRESERVATION.md) | PLANNED | Preserve clap derives so obfuscated binaries keep their CLI interface |

## Architecture Summary

```
src/
├── main.rs          # CLI (clap derive)
├── lib.rs           # Public API
├── error.rs         # ApateError (thiserror)
├── key.rs           # Key gen/load/derive
├── manifest.rs      # Encrypted transform manifest
├── pipeline.rs      # Pass orchestration
├── semantic.rs      # rust-analyzer integration (SemanticAnalyzer, LocalDefMap)
├── passes/
│   ├── mod.rs       # ObfuscationPass trait + PassContext + registry
│   ├── strip.rs     # Pass 1: Comment stripping
│   ├── rename.rs    # Pass 2: Identifier renaming
│   ├── homoglyph.rs # Pass 3: Unicode homoglyphs
│   ├── logic.rs     # Pass 4: Control-flow obfuscation
│   ├── dead_code.rs # Pass 5: Dead code injection
│   ├── strings.rs   # Pass 6: String encoding
│   └── reorder.rs   # Pass 7: Item reordering
└── utils/
    ├── mod.rs
    ├── ast.rs        # AST helpers
    ├── crypto.rs     # HMAC, BLAKE3, XOR helpers
    └── homoglyphs.rs # Unicode mapping tables
```

## Key Design Decisions

- **Edition 2024** — latest Rust edition
- **Keyed determinism** — all randomness from `BLAKE3(master_key || file_path)` seeded ChaCha20Rng
- **Pass trait** — every pass implements `encrypt()` + `decrypt()`, returns `PassRecord`
- **Manifest** — JSON serialized, AES-256-GCM encrypted with derived key
- **Pipeline order** — encrypt: 1→7, decrypt: 7→1 (reverse)
