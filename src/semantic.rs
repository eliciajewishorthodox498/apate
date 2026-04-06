//! Semantic analysis using rust-analyzer's libraries.
//!
//! Loads a Cargo workspace into RA's analysis database and builds a `LocalDefMap`
//! mapping every locally-defined module-level identifier occurrence (by file path
//! + byte range) so the rename pass knows which identifiers are safe to rename.
//!
//! Local variables and function parameters are NOT tracked here — they are always
//! local by definition and handled by the heuristic rename path directly.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use ra_ap_hir as hir;
use ra_ap_hir_ty as hir_ty;
use ra_ap_ide_db as ide_db;
use ra_ap_load_cargo as load_cargo;
use ra_ap_project_model as project_model;
use ra_ap_vfs as vfs;

use ra_ap_ide::TryToNav;

use ide_db::defs::Definition;
use ide_db::search::SearchScope;
use ide_db::RootDatabase;
use load_cargo::{LoadCargoConfig, ProcMacroServerChoice};
use project_model::CargoConfig;

use crate::error::{ApateError, Result};

/// Maps every local module-level identifier occurrence to its original name.
///
/// Key: (relative file path, byte start offset, byte end offset)
/// Value: the original identifier name
///
/// Only tracks module-level definitions (structs, functions, enums, fields,
/// traits, impl methods, consts, statics) — the identifiers where local vs
/// external is ambiguous. Local variables and parameters are always local
/// and don't need semantic analysis.
pub struct LocalDefMap {
    pub refs: HashMap<(PathBuf, u32, u32), String>,
}

impl LocalDefMap {
    /// Look up whether a byte range in a file is a local identifier reference.
    pub fn get(&self, file: &Path, start: u32, end: u32) -> Option<&str> {
        self.refs
            .get(&(file.to_path_buf(), start, end))
            .map(|s| s.as_str())
    }

    pub fn len(&self) -> usize {
        self.refs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.refs.is_empty()
    }
}

/// Loads a Cargo workspace and provides semantic analysis via rust-analyzer.
pub struct SemanticAnalyzer {
    db: RootDatabase,
    #[allow(dead_code)]
    vfs: vfs::Vfs,
    /// Map from VFS FileId → relative file path
    file_paths: HashMap<vfs::FileId, PathBuf>,
    /// Absolute path to the crate root directory
    crate_dir: PathBuf,
}

impl SemanticAnalyzer {
    /// Load a Cargo workspace into RA's analysis database.
    pub fn load(crate_dir: &Path) -> Result<Self> {
        let crate_dir = std::path::absolute(crate_dir).map_err(|e| ApateError::PassFailed {
            pass: "semantic".into(),
            reason: format!("failed to resolve absolute path: {e}"),
        })?;

        let cargo_config = CargoConfig::default();
        let load_config = LoadCargoConfig {
            load_out_dirs_from_check: false,
            with_proc_macro_server: ProcMacroServerChoice::None,
            prefill_caches: false,
            num_worker_threads: 0, // 0 = use all available CPU cores
            proc_macro_processes: 0,
        };

        let (db, vfs, _proc_macro) = load_cargo::load_workspace_at(
            &crate_dir,
            &cargo_config,
            &load_config,
            &|msg| {
                eprint!("\r  · Analyzing: {msg:<60}");
            },
        )
        .map_err(|e| ApateError::PassFailed {
            pass: "semantic".into(),
            reason: format!("failed to load workspace: {e}"),
        })?;

        // Build file path map: FileId → relative path from crate root
        let mut file_paths = HashMap::new();
        for (file_id, vfs_path) in vfs.iter() {
            if let Some(abs_path) = vfs_path.as_path() {
                let abs_buf: PathBuf = AsRef::<Path>::as_ref(abs_path).to_path_buf();
                if let Ok(rel) = abs_buf.strip_prefix(&crate_dir) {
                    file_paths.insert(file_id, rel.to_path_buf());
                }
            }
        }

        Ok(Self {
            db,
            vfs,
            file_paths,
            crate_dir: crate_dir.to_path_buf(),
        })
    }

    /// Build the LocalDefMap by iterating all local definitions and finding
    /// all their reference sites.
    pub fn build_local_def_map(&self) -> Result<LocalDefMap> {
        // RA's hir_ty requires the DB to be "attached" to the thread-local context
        // before any type inference queries run.
        hir_ty::attach_db(&self.db, || self.build_local_def_map_inner())
    }

    fn build_local_def_map_inner(&self) -> Result<LocalDefMap> {
        let sema = hir::Semantics::new(&self.db);
        let mut refs = HashMap::new();

        // Build workspace search scope — restricts usages search to local files only,
        // preventing RA from scanning dependency source (which can never reference us).
        let workspace_file_ids: Vec<_> = self
            .file_paths
            .keys()
            .map(|&vfs_id| {
                ide_db::base_db::EditionedFileId::current_edition(&self.db, vfs_id)
            })
            .collect();
        let workspace_scope = SearchScope::files(&workspace_file_ids);

        // Only iterate workspace crates — krate.origin().is_local() filters out
        // ALL external dependencies (registry crates, lang crates, rustc crates).
        for krate in hir::Crate::all(&self.db) {
            if !krate.origin(&self.db).is_local() {
                continue;
            }

            for module in krate.modules(&self.db) {
                // Module-level declarations (functions, structs, enums, traits, etc.)
                for def in module.declarations(&self.db) {
                    self.collect_def_refs(
                        &sema,
                        Definition::from(def),
                        &mut refs,
                        &workspace_scope,
                    );

                    // For enums: collect variant names (path-based, safe to rename).
                    // Skip: trait items (need type inference for dynamic dispatch),
                    //        struct/enum/union fields (need type inference for dot access).
                    // Only rename identifiers resolved via path syntax, not dot notation.
                    if let hir::ModuleDef::Adt(hir::Adt::Enum(e)) = def {
                        for variant in e.variants(&self.db) {
                            self.collect_def_refs(
                                &sema,
                                Definition::Variant(variant),
                                &mut refs,
                                &workspace_scope,
                            );
                        }
                    }
                }

                // Inherent impl items only (methods on concrete types, not traits).
                // Skip ALL trait impls — trait method names form a contract across
                // definition, impls, and call sites. RA can't reliably find dynamic
                // dispatch call sites (Box<dyn Trait>), so renaming trait methods
                // causes definition/usage mismatches.
                for impl_def in module.impl_defs(&self.db) {
                    if impl_def.trait_(&self.db).is_some() {
                        continue;
                    }

                    for item in impl_def.items(&self.db) {
                        let def = match item {
                            hir::AssocItem::Function(f) => Definition::Function(f),
                            hir::AssocItem::Const(c) => Definition::Const(c),
                            hir::AssocItem::TypeAlias(t) => Definition::TypeAlias(t),
                        };
                        self.collect_def_refs(&sema, def, &mut refs, &workspace_scope);
                    }
                }
            }
        }

        // Normalize byte offsets from CRLF (raw file) to LF (proc_macro2/syn).
        // RA returns byte ranges based on raw file content (CRLF on Windows),
        // but proc_macro2 spans use LF-normalized positions. Adjust here so
        // lookups in SemanticRenamer match correctly.
        let refs = self.normalize_crlf_offsets(refs, &self.crate_dir);

        Ok(LocalDefMap { refs })
    }

    /// Convert CRLF-based byte offsets to LF-based offsets.
    ///
    /// RA returns byte ranges based on raw file content (CRLF on Windows),
    /// but proc_macro2 spans use LF-normalized positions. For each file,
    /// count `\r` bytes before each offset position and subtract them.
    fn normalize_crlf_offsets(
        &self,
        refs: HashMap<(PathBuf, u32, u32), String>,
        crate_dir: &Path,
    ) -> HashMap<(PathBuf, u32, u32), String> {
        let mut cr_positions: HashMap<PathBuf, Vec<u32>> = HashMap::new();

        let mut normalized = HashMap::new();
        for ((file, start, end), name) in refs {
            let crs = cr_positions.entry(file.clone()).or_insert_with(|| {
                let abs_path = crate_dir.join(&file);
                match std::fs::read(&abs_path) {
                    Ok(contents) => contents
                        .iter()
                        .enumerate()
                        .filter(|(_, b)| **b == b'\r')
                        .map(|(i, _)| i as u32)
                        .collect(),
                    Err(_) => Vec::new(),
                }
            });

            let cr_before_start = crs.partition_point(|&pos| pos < start) as u32;
            let cr_before_end = crs.partition_point(|&pos| pos < end) as u32;

            normalized.insert(
                (file, start - cr_before_start, end - cr_before_end),
                name,
            );
        }
        normalized
    }

    /// Collect all reference sites for a single definition within a search scope.
    fn collect_def_refs(
        &self,
        sema: &hir::Semantics<'_, RootDatabase>,
        def: Definition,
        refs: &mut HashMap<(PathBuf, u32, u32), String>,
        scope: &SearchScope,
    ) {
        let name = match def.name(&self.db) {
            Some(n) => n.as_str().to_string(),
            None => return,
        };

        if should_skip_def(&def, &self.db) {
            return;
        }

        // Find usages FIRST — scoped to workspace files only.
        let usages = def.usages(sema).in_scope(scope).all();
        let has_usages = usages.iter().any(|(_, file_refs)| !file_refs.is_empty());

        // Only record if RA found at least one usage site.
        // If zero usages: either dead code or RA couldn't resolve them
        // (e.g., field access without full type inference). Either way,
        // renaming the definition without renaming usage sites breaks the code.
        // Better to leave it un-renamed than half-renamed.
        if !has_usages {
            return;
        }

        // Record the definition site.
        if let Some(nav_result) = def.try_to_nav(sema) {
            let nav = nav_result.call_site;
            if let Some(rel_path) = self.file_id_to_path(nav.file_id) {
                let range = nav.focus_range.unwrap_or(nav.full_range);
                refs.insert(
                    (rel_path, range.start().into(), range.end().into()),
                    name.clone(),
                );
            }
        }

        // Record usage sites.
        for (file_id, file_refs) in usages.iter() {
            let raw_file_id = file_id.file_id(&self.db);
            if let Some(rel_path) = self.file_id_to_path(raw_file_id) {
                for file_ref in file_refs {
                    let range = file_ref.range;
                    refs.insert(
                        (
                            rel_path.clone(),
                            range.start().into(),
                            range.end().into(),
                        ),
                        name.clone(),
                    );
                }
            }
        }
    }

    /// Convert a raw file ID to a relative path.
    fn file_id_to_path(&self, file_id: ide_db::base_db::FileId) -> Option<PathBuf> {
        // RA's FileId maps directly to VFS FileId
        let vfs_id = vfs::FileId::from_raw(file_id.index());
        self.file_paths.get(&vfs_id).cloned()
    }
}

/// Check if a definition should be skipped (not renamed).
fn should_skip_def(def: &Definition, db: &RootDatabase) -> bool {
    match def {
        Definition::Function(f) => {
            let name = f.name(db).as_str().to_string();
            name == "main"
        }
        Definition::BuiltinType(_)
        | Definition::BuiltinLifetime(_)
        | Definition::BuiltinAttr(_) => true,
        Definition::Module(_) => true,
        _ => false,
    }
}
