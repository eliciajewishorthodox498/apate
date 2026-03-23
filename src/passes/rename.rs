use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use proc_macro2::{TokenStream, TokenTree};
use serde::{Deserialize, Serialize};
use syn::visit::Visit;
use syn::visit_mut::VisitMut;

use crate::error::{ApateError, Result};
use crate::passes::{ObfuscationPass, PassContext, PassRecord};
use crate::semantic::LocalDefMap;
use crate::utils::crypto;

/// Rename pass — deterministically renames all local identifiers to hostile names.
pub struct RenamePass;

#[derive(Debug, Serialize, Deserialize)]
struct RenameData {
    /// Original name → obfuscated name mapping.
    mapping: HashMap<String, String>,
}

/// Pre-pass: collect ITEM-LEVEL definitions from a file (types, functions, constants).
///
/// Only collects names that are visible across files — NOT local variables,
/// parameters, or inner bindings. Used by encrypt_crate to pre-populate the
/// ident_registry so cross-file references resolve correctly.
pub fn collect_file_definitions(
    ast: &syn::File,
    master_key: &[u8; 32],
    registry: &mut HashMap<String, String>,
    crate_info: Option<&crate::cargo_info::CrateInfo>,
    _preserve_public: bool,
) {
    let mut blocklist = static_blocklist();
    if let Some(info) = crate_info {
        blocklist.extend(info.external_crates.iter().cloned());
    }

    let hmac_key = crate::key::derive_subkey(master_key, crate::key::HMAC_CONTEXT);

    // Only collect top-level item definitions (not local vars/params)
    for item in &ast.items {
        let names = collect_item_names(item);
        for name in names {
            if !blocklist.contains(&name) && !registry.contains_key(&name) {
                let obfuscated = generate_obfuscated_name(&name, &hmac_key);
                registry.insert(name, obfuscated);
            }
        }
    }
}

/// Extract defined names from a top-level item (functions, types, constants, etc.)
fn collect_item_names(item: &syn::Item) -> Vec<String> {
    let mut names = Vec::new();
    match item {
        syn::Item::Fn(f) => {
            let name = f.sig.ident.to_string();
            if name != "main" && f.sig.abi.is_none() {
                names.push(name);
            }
        }
        syn::Item::Struct(s) => {
            names.push(s.ident.to_string());
            for field in &s.fields {
                if let Some(ref ident) = field.ident {
                    names.push(ident.to_string());
                }
            }
        }
        syn::Item::Enum(e) => {
            names.push(e.ident.to_string());
            for variant in &e.variants {
                names.push(variant.ident.to_string());
            }
        }
        syn::Item::Trait(t) => {
            names.push(t.ident.to_string());
            // Don't collect trait method names — they must match across impls
        }
        syn::Item::Type(t) => names.push(t.ident.to_string()),
        syn::Item::Const(c) => names.push(c.ident.to_string()),
        syn::Item::Static(s) => names.push(s.ident.to_string()),
        syn::Item::Impl(imp) => {
            // Only collect method names from inherent impls (no trait)
            if imp.trait_.is_none() {
                for item in &imp.items {
                    if let syn::ImplItem::Fn(f) = item {
                        names.push(f.sig.ident.to_string());
                    }
                }
            }
        }
        _ => {}
    }
    names
}

impl ObfuscationPass for RenamePass {
    fn name(&self) -> &'static str {
        "rename"
    }

    fn encrypt(
        &self,
        ast: &mut syn::File,
        context: &mut PassContext,
    ) -> Result<PassRecord> {
        // When LocalDefMap is available, use position-based renaming.
        // Otherwise, fall back to heuristic name-based renaming.
        if context.local_def_map.is_some() {
            return self.encrypt_semantic(ast, context);
        }

        // ---- Heuristic fallback (no RA analysis available) ----

        // Phase A: Collect all locally-defined identifiers
        let mut collector = IdentCollector::new(context.preserve_public, context.crate_info.as_ref());
        collector.visit_file(ast);

        // Build the dynamic blocklist from derive macros + external crate names
        let mut blocklist = static_blocklist();
        blocklist.extend(collector.derive_idents.iter().cloned());
        if let Some(ref info) = context.crate_info {
            blocklist.extend(info.external_crates.iter().cloned());
        }

        let local_defs: HashSet<String> = collector
            .local_defs
            .difference(&blocklist)
            .cloned()
            .collect();

        // Phase B: Generate obfuscated names for each local definition
        let mut mapping = HashMap::new();

        // Add cross-file mappings for items imported via `use crate::...`
        for name in &collector.imported_items {
            if let Some(obf) = context.ident_registry.get(name.as_str()) {
                mapping.insert(name.clone(), obf.clone());
            }
        }

        for name in &local_defs {
            if context.ident_registry.contains_key(name.as_str()) {
                mapping.insert(
                    name.clone(),
                    context.ident_registry[name.as_str()].clone(),
                );
            } else {
                let obfuscated = generate_obfuscated_name(name, &context.hmac_key);
                context
                    .ident_registry
                    .insert(name.clone(), obfuscated.clone());
                mapping.insert(name.clone(), obfuscated);
            }
        }

        // Phase C: Walk AST and replace identifiers
        let empty_set = HashSet::new();
        let external_crates = context.crate_info.as_ref()
            .map(|i| &i.external_crates)
            .unwrap_or(&empty_set);
        let crate_name = context.crate_info.as_ref()
            .map(|i| i.crate_name.as_str());

        let cross_file_exports: HashMap<String, String> = context
            .ident_registry
            .iter()
            .filter(|(name, _)| !blocklist.contains(*name))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let mut renamer = IdentRenamer {
            mapping: &mapping,
            cross_file_registry: &cross_file_exports,
            local_struct_names: &collector.local_struct_names,
            local_trait_names: &collector.local_trait_names,
            local_modules: &collector.local_modules,
            external_crates,
            crate_name,
            in_external_trait_impl: false,
        };
        renamer.visit_file_mut(ast);

        let data = RenameData {
            mapping: mapping.clone(),
        };

        Ok(PassRecord {
            pass_name: self.name().to_string(),
            data: serde_json::to_value(data).expect("RenameData serializes"),
        })
    }

    fn decrypt(
        &self,
        ast: &mut syn::File,
        record: &PassRecord,
        _context: &PassContext,
    ) -> Result<()> {
        let data: RenameData =
            serde_json::from_value(record.data.clone()).map_err(|e| ApateError::PassFailed {
                pass: "rename".into(),
                reason: format!("failed to deserialize rename data: {e}"),
            })?;

        // Build reverse mapping: obfuscated → original
        let reverse: HashMap<String, String> = data
            .mapping
            .iter()
            .map(|(orig, obf)| (obf.clone(), orig.clone()))
            .collect();

        // For decrypt, all struct/trait names in the mapping are "local" (they were renamed)
        let local_struct_names: HashSet<String> = reverse.values().cloned().collect();
        let local_trait_names: HashSet<String> = reverse.values().cloned().collect();
        // For decrypt, collect local modules from the AST as-is (with obfuscated names)
        let mut decrypt_collector = IdentCollector::new(false, None);
        decrypt_collector.visit_file(ast);
        let local_modules = decrypt_collector.local_modules;
        let empty_set = HashSet::new();

        let empty_map = HashMap::new();
        let mut renamer = IdentRenamer {
            mapping: &reverse,
            cross_file_registry: &empty_map,
            local_struct_names: &local_struct_names,
            local_trait_names: &local_trait_names,
            local_modules: &local_modules,
            external_crates: &empty_set,
            crate_name: None,
            in_external_trait_impl: false,
        };
        renamer.visit_file_mut(ast);

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Position-based rename (SemanticRenamer) — used when LocalDefMap is available
// ---------------------------------------------------------------------------

impl RenamePass {
    /// Position-based rename using RA's LocalDefMap.
    ///
    /// For every Ident in the AST, compute its byte offset and check the map.
    /// If found → rename. If not → skip. No blocklists, no heuristics.
    fn encrypt_semantic(
        &self,
        ast: &mut syn::File,
        context: &mut PassContext,
    ) -> Result<PassRecord> {
        let ldm = context.local_def_map.as_ref().unwrap();
        let query_file = context
            .relative_file
            .as_deref()
            .unwrap_or(context.current_file.as_path());

        // The original source text — must match what RA analyzed.
        // Normalize CRLF → LF to match proc_macro2 and RA's internal representation.
        let source = context
            .original_source
            .as_deref()
            .expect("original_source required for semantic rename")
            .replace("\r\n", "\n");
        let line_starts = build_line_starts(&source);

        // Build the mapping: for every unique name in the LocalDefMap for this file,
        // generate (or reuse) an obfuscated name.
        let mut mapping: HashMap<String, String> = HashMap::new();
        for ((file, _, _), name) in &ldm.refs {
            if file.as_path() != query_file {
                continue;
            }
            if mapping.contains_key(name) {
                continue;
            }
            let obfuscated = if let Some(existing) = context.ident_registry.get(name.as_str()) {
                existing.clone()
            } else {
                let obf = generate_obfuscated_name(name, &context.hmac_key);
                context.ident_registry.insert(name.clone(), obf.clone());
                obf
            };
            mapping.insert(name.clone(), obfuscated);
        }

        // Walk AST with position-based renamer
        let mut renamer = SemanticRenamer {
            local_def_map: Arc::clone(ldm),
            query_file: query_file.to_path_buf(),
            line_starts,
            mapping: &mapping,
        };
        renamer.visit_file_mut(ast);

        let data = RenameData {
            mapping: mapping.clone(),
        };

        Ok(PassRecord {
            pass_name: "rename".to_string(),
            data: serde_json::to_value(data).expect("RenameData serializes"),
        })
    }
}

/// Build line-start byte offsets for the byte-offset bridge.
fn build_line_starts(source: &str) -> Vec<usize> {
    let mut starts = vec![0];
    for (i, byte) in source.bytes().enumerate() {
        if byte == b'\n' {
            starts.push(i + 1);
        }
    }
    starts
}

/// Convert a proc_macro2 span start to an absolute byte offset.
fn span_to_byte_range(ident: &proc_macro2::Ident, line_starts: &[usize]) -> (u32, u32) {
    let start = ident.span().start();
    let line_idx = start.line.saturating_sub(1);
    let byte_start = (line_starts.get(line_idx).copied().unwrap_or(0) + start.column) as u32;
    let byte_end = byte_start + (ident.to_string().len() as u32);
    (byte_start, byte_end)
}

/// Position-based renamer: checks every Ident against the LocalDefMap by byte offset.
struct SemanticRenamer<'a> {
    local_def_map: Arc<LocalDefMap>,
    query_file: std::path::PathBuf,
    line_starts: Vec<usize>,
    mapping: &'a HashMap<String, String>,
}

impl<'a> SemanticRenamer<'a> {
    /// Position-only rename: check the LocalDefMap by byte offset.
    fn try_rename(&self, ident: &mut syn::Ident) {
        let (byte_start, byte_end) = span_to_byte_range(ident, &self.line_starts);
        if let Some(original_name) = self.local_def_map.get(&self.query_file, byte_start, byte_end)
        {
            if let Some(replacement) = self.mapping.get(original_name) {
                *ident = syn::Ident::new(replacement, ident.span());
            }
        }
    }

    /// Position-based rename with name-based fallback for RA misses.
    ///
    /// Used for field access, struct literal fields, and pattern fields — positions
    /// where RA's type inference may not resolve the receiver but where the name-based
    /// fallback is safe (these can't be external module paths or crate names).
    fn try_rename_with_fallback(&self, ident: &mut syn::Ident) {
        let (byte_start, byte_end) = span_to_byte_range(ident, &self.line_starts);
        if let Some(original_name) = self.local_def_map.get(&self.query_file, byte_start, byte_end)
        {
            if let Some(replacement) = self.mapping.get(original_name) {
                *ident = syn::Ident::new(replacement, ident.span());
                return;
            }
        }
        // Fallback: name-based (safe here — fields can't be external paths)
        let name = ident.to_string();
        if let Some(replacement) = self.mapping.get(&name) {
            *ident = syn::Ident::new(replacement, ident.span());
        }
    }

    /// Rename idents inside macro token streams by byte offset.
    fn rename_token_stream(&self, tokens: &TokenStream) -> TokenStream {
        tokens
            .clone()
            .into_iter()
            .map(|tt| match tt {
                TokenTree::Ident(ref ident) => {
                    let (byte_start, byte_end) =
                        span_to_byte_range(ident, &self.line_starts);
                    if let Some(original_name) =
                        self.local_def_map.get(&self.query_file, byte_start, byte_end)
                    {
                        if let Some(replacement) = self.mapping.get(original_name) {
                            return TokenTree::Ident(proc_macro2::Ident::new(
                                replacement,
                                ident.span(),
                            ));
                        }
                    }
                    tt
                }
                TokenTree::Group(group) => {
                    let renamed = self.rename_token_stream(&group.stream());
                    let mut new_group =
                        proc_macro2::Group::new(group.delimiter(), renamed);
                    new_group.set_span(group.span());
                    TokenTree::Group(new_group)
                }
                TokenTree::Literal(ref lit) => {
                    // Rewrite format string interpolation: {var} → {renamed_var}
                    let repr = lit.to_string();
                    if repr.starts_with('"') && repr.contains('{') {
                        let rewritten = self.rename_format_string(&repr);
                        if rewritten != repr {
                            if let Ok(new_lit) = rewritten.parse::<proc_macro2::Literal>() {
                                return TokenTree::Literal(new_lit);
                            }
                        }
                    }
                    tt
                }
                _ => tt,
            })
            .collect()
    }

    /// Rewrite `{ident}` and `{ident:fmt}` patterns inside a format string literal.
    fn rename_format_string(&self, lit_repr: &str) -> String {
        let mut result = String::with_capacity(lit_repr.len());
        let mut chars = lit_repr.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '{' {
                let mut inner = String::new();
                let mut found_close = false;
                for ic in chars.by_ref() {
                    if ic == '}' {
                        found_close = true;
                        break;
                    }
                    inner.push(ic);
                }
                if found_close {
                    let (ident_part, spec_part) = match inner.find(':') {
                        Some(pos) => (&inner[..pos], &inner[pos..]),
                        None => (inner.as_str(), ""),
                    };
                    if let Some(replacement) = self.mapping.get(ident_part) {
                        result.push('{');
                        result.push_str(replacement);
                        result.push_str(spec_part);
                        result.push('}');
                    } else {
                        result.push('{');
                        result.push_str(&inner);
                        result.push('}');
                    }
                } else {
                    result.push('{');
                    result.push_str(&inner);
                }
            } else {
                result.push(c);
            }
        }
        result
    }
}

impl VisitMut for SemanticRenamer<'_> {
    // syn's default VisitMut does NOT call visit_ident_mut for idents embedded
    // inside path segments, field members, method calls, etc. We need explicit
    // visitors for each position. Every one uses the same try_rename logic —
    // byte offset check against the LocalDefMap, no special casing.

    // --- Definition sites ---

    // Definition sites use fallback — they're always local definitions in this file.
    fn visit_item_fn_mut(&mut self, node: &mut syn::ItemFn) {
        self.try_rename(&mut node.sig.ident);
        syn::visit_mut::visit_item_fn_mut(self, node);
    }

    fn visit_item_struct_mut(&mut self, node: &mut syn::ItemStruct) {
        self.try_rename(&mut node.ident);
        syn::visit_mut::visit_item_struct_mut(self, node);
    }

    fn visit_item_enum_mut(&mut self, node: &mut syn::ItemEnum) {
        self.try_rename(&mut node.ident);
        syn::visit_mut::visit_item_enum_mut(self, node);
    }

    fn visit_item_union_mut(&mut self, node: &mut syn::ItemUnion) {
        self.try_rename(&mut node.ident);
        syn::visit_mut::visit_item_union_mut(self, node);
    }

    fn visit_item_trait_mut(&mut self, node: &mut syn::ItemTrait) {
        self.try_rename(&mut node.ident);
        syn::visit_mut::visit_item_trait_mut(self, node);
    }

    fn visit_item_type_mut(&mut self, node: &mut syn::ItemType) {
        self.try_rename(&mut node.ident);
        syn::visit_mut::visit_item_type_mut(self, node);
    }

    fn visit_item_const_mut(&mut self, node: &mut syn::ItemConst) {
        self.try_rename(&mut node.ident);
        syn::visit_mut::visit_item_const_mut(self, node);
    }

    fn visit_item_static_mut(&mut self, node: &mut syn::ItemStatic) {
        self.try_rename(&mut node.ident);
        syn::visit_mut::visit_item_static_mut(self, node);
    }

    fn visit_variant_mut(&mut self, node: &mut syn::Variant) {
        self.try_rename(&mut node.ident);
        syn::visit_mut::visit_variant_mut(self, node);
    }

    fn visit_field_mut(&mut self, node: &mut syn::Field) {
        if let Some(ref mut ident) = node.ident {
            self.try_rename(ident);
        }
        syn::visit_mut::visit_field_mut(self, node);
    }

    fn visit_impl_item_fn_mut(&mut self, node: &mut syn::ImplItemFn) {
        self.try_rename(&mut node.sig.ident);
        syn::visit_mut::visit_impl_item_fn_mut(self, node);
    }

    fn visit_trait_item_fn_mut(&mut self, node: &mut syn::TraitItemFn) {
        self.try_rename(&mut node.sig.ident);
        syn::visit_mut::visit_trait_item_fn_mut(self, node);
    }

    // Pat idents and generics — position-only (no fallback).
    // Body-level locals aren't in the LocalDefMap, so they won't be renamed.
    // Using fallback here would rename the binding but not the usage sites
    // (which are path segments with position-only check) → mismatch.
    fn visit_pat_ident_mut(&mut self, node: &mut syn::PatIdent) {
        self.try_rename(&mut node.ident);
        syn::visit_mut::visit_pat_ident_mut(self, node);
    }

    fn visit_generic_param_mut(&mut self, node: &mut syn::GenericParam) {
        match node {
            syn::GenericParam::Type(tp) => self.try_rename(&mut tp.ident),
            syn::GenericParam::Const(cp) => self.try_rename(&mut cp.ident),
            _ => {}
        }
        syn::visit_mut::visit_generic_param_mut(self, node);
    }

    // --- Usage sites ---

    fn visit_path_segment_mut(&mut self, node: &mut syn::PathSegment) {
        self.try_rename(&mut node.ident);
        syn::visit_mut::visit_path_segment_mut(self, node);
    }

    // Usage sites — position-only (no fallback). These could be on external types
    // where RA didn't resolve the receiver, and name-based fallback would cause
    // false positives (renaming .get() on HashMap, .path() on walkdir, etc.).
    fn visit_expr_field_mut(&mut self, node: &mut syn::ExprField) {
        if let syn::Member::Named(ref mut ident) = node.member {
            self.try_rename(ident);
        }
        syn::visit_mut::visit_expr_field_mut(self, node);
    }

    fn visit_expr_method_call_mut(&mut self, node: &mut syn::ExprMethodCall) {
        self.try_rename(&mut node.method);
        syn::visit_mut::visit_expr_method_call_mut(self, node);
    }

    fn visit_field_value_mut(&mut self, node: &mut syn::FieldValue) {
        if let syn::Member::Named(ref mut ident) = node.member {
            self.try_rename(ident);
        }
        syn::visit_mut::visit_field_value_mut(self, node);
    }

    fn visit_field_pat_mut(&mut self, node: &mut syn::FieldPat) {
        if let syn::Member::Named(ref mut ident) = node.member {
            self.try_rename(ident);
        }
        syn::visit_mut::visit_field_pat_mut(self, node);
    }

    // --- Use statements ---

    fn visit_use_tree_mut(&mut self, node: &mut syn::UseTree) {
        match node {
            syn::UseTree::Name(name) => self.try_rename(&mut name.ident),
            syn::UseTree::Rename(rename) => self.try_rename(&mut rename.ident),
            _ => {}
        }
        syn::visit_mut::visit_use_tree_mut(self, node);
    }

    // --- Macro bodies (opaque token streams) ---

    fn visit_macro_mut(&mut self, node: &mut syn::Macro) {
        node.tokens = self.rename_token_stream(&node.tokens);
    }

    // --- Attributes: only rename inside #[error("...")] for thiserror ---

    fn visit_attribute_mut(&mut self, node: &mut syn::Attribute) {
        if node.path().is_ident("error") {
            if let syn::Meta::List(ref mut meta_list) = node.meta {
                meta_list.tokens = self.rename_token_stream(&meta_list.tokens);
            }
        }
    }
}

/// Generate a hostile-looking obfuscated name from an identifier.
///
/// The naming strategy is derived from the HMAC hash itself (not the RNG),
/// so the result is deterministic regardless of processing order.
fn generate_obfuscated_name(original: &str, hmac_key: &[u8]) -> String {
    let hash = crypto::hmac_sha256(hmac_key, original.as_bytes());
    // Use a hash byte to select strategy — independent of RNG/iteration order
    let strategy = hash[31] % 4;

    match strategy {
        // _x + hex fragment
        0 => {
            let hex: String = hash[..3].iter().map(|b| format!("{b:02x}")).collect();
            format!("_x{hex}")
        }
        // Confusing l/1/I/O/0 mix
        1 => {
            let chars = ['l', '1', 'I', 'O', '0', 'l'];
            let suffix: String = hash[..4]
                .iter()
                .map(|b| chars[(*b as usize) % chars.len()])
                .collect();
            format!("_{suffix}")
        }
        // Double underscore + short hash
        2 => {
            let hex: String = hash[..2].iter().map(|b| format!("{b:02x}")).collect();
            format!("__{hex}")
        }
        // Single letter + digits
        3 => {
            let letter = (b'a' + (hash[0] % 26)) as char;
            let digits: String = hash[1..3].iter().map(|b| format!("{}", b % 10)).collect();
            format!("_{letter}{digits}")
        }
        _ => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// Phase A: Identifier collection (read-only AST walk)
// ---------------------------------------------------------------------------

struct IdentCollector {
    local_defs: HashSet<String>,
    /// Body-level locals only (let bindings, function params, match arms, generics).
    /// These are always local by definition — no semantic analysis needed.
    body_locals: HashSet<String>,
    derive_idents: HashSet<String>,
    local_struct_names: HashSet<String>,
    local_trait_names: HashSet<String>,
    local_modules: HashSet<String>,
    /// Item names imported from internal use statements (e.g., `use crate::error::{ApateError, Result}`
    /// → contains "ApateError", "Result"). These need cross-file registry lookups.
    imported_items: HashSet<String>,
    /// The crate's own name (from Cargo.toml), if known.
    crate_name: Option<String>,
    preserve_public: bool,
    in_external_trait_impl: bool,
}

impl IdentCollector {
    fn new(preserve_public: bool, crate_info: Option<&crate::cargo_info::CrateInfo>) -> Self {
        Self {
            local_defs: HashSet::new(),
            body_locals: HashSet::new(),
            derive_idents: HashSet::new(),
            local_struct_names: HashSet::new(),
            local_trait_names: HashSet::new(),
            local_modules: HashSet::new(),
            imported_items: HashSet::new(),
            crate_name: crate_info.map(|i| i.crate_name.clone()),
            preserve_public,
            in_external_trait_impl: false,
        }
    }

    fn add(&mut self, name: &str) {
        self.local_defs.insert(name.to_string());
    }

    /// Check if an item should be skipped due to bare `pub` visibility.
    fn is_preserved_public(&self, vis: &syn::Visibility) -> bool {
        self.preserve_public && matches!(vis, syn::Visibility::Public(_))
    }

    /// Check if a function should be excluded from renaming based on its attributes.
    fn is_pinned_fn(attrs: &[syn::Attribute]) -> bool {
        for attr in attrs {
            let path = attr.path();
            if path.is_ident("test")
                || path.is_ident("no_mangle")
                || path.is_ident("tokio")
                || path.is_ident("async_std")
            {
                return true;
            }
            // Check for #[export_name = "..."]
            if path.is_ident("export_name") {
                return true;
            }
        }
        false
    }

    /// Extract idents from #[derive(...)] attributes.
    fn collect_derive_idents(&mut self, attrs: &[syn::Attribute]) {
        for attr in attrs {
            if attr.path().is_ident("derive")
                && let Ok(nested) = attr.parse_args_with(
                    syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
                )
            {
                for path in nested {
                    if let Some(ident) = path.get_ident() {
                        self.derive_idents.insert(ident.to_string());
                    }
                    // Also grab the last segment for paths like serde::Serialize
                    if let Some(last) = path.segments.last() {
                        self.derive_idents.insert(last.ident.to_string());
                    }
                }
            }
        }
    }

    /// Check if a trait path refers to a locally-defined trait.
    fn is_local_trait(&self, path: &syn::Path) -> bool {
        if let Some(last) = path.segments.last() {
            self.local_trait_names.contains(&last.ident.to_string())
        } else {
            false
        }
    }
}

impl<'ast> Visit<'ast> for IdentCollector {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let name = node.sig.ident.to_string();
        if name != "main"
            && !Self::is_pinned_fn(&node.attrs)
            && !self.is_preserved_public(&node.vis)
            && node.sig.abi.is_none()
        {
            self.add(&name);
        }
        self.collect_derive_idents(&node.attrs);
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        self.local_modules.insert(node.ident.to_string());
        syn::visit::visit_item_mod(self, node);
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        // Collect module names and imported item names from internal use statements.
        collect_use_modules(&node.tree, &mut self.local_modules, &mut self.imported_items, self.crate_name.as_deref());
        syn::visit::visit_item_use(self, node);
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        let name = node.ident.to_string();
        self.local_struct_names.insert(name.clone());
        if !self.is_preserved_public(&node.vis) {
            self.add(&name);
        }
        self.collect_derive_idents(&node.attrs);
        syn::visit::visit_item_struct(self, node);
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        let name = node.ident.to_string();
        self.local_struct_names.insert(name.clone());
        if !self.is_preserved_public(&node.vis) {
            self.add(&name);
        }
        self.collect_derive_idents(&node.attrs);
        syn::visit::visit_item_enum(self, node);
    }

    fn visit_item_union(&mut self, node: &'ast syn::ItemUnion) {
        let name = node.ident.to_string();
        self.local_struct_names.insert(name.clone());
        if !self.is_preserved_public(&node.vis) {
            self.add(&name);
        }
        self.collect_derive_idents(&node.attrs);
        syn::visit::visit_item_union(self, node);
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        let name = node.ident.to_string();
        self.local_trait_names.insert(name.clone());
        if !self.is_preserved_public(&node.vis) {
            self.add(&name);
        }
        self.collect_derive_idents(&node.attrs);
        syn::visit::visit_item_trait(self, node);
    }

    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        if !self.is_preserved_public(&node.vis) {
            self.add(&node.ident.to_string());
        }
        syn::visit::visit_item_type(self, node);
    }

    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        if !self.is_preserved_public(&node.vis) {
            self.add(&node.ident.to_string());
        }
        syn::visit::visit_item_const(self, node);
    }

    fn visit_item_static(&mut self, node: &'ast syn::ItemStatic) {
        if !self.is_preserved_public(&node.vis) {
            self.add(&node.ident.to_string());
        }
        syn::visit::visit_item_static(self, node);
    }

    fn visit_variant(&mut self, node: &'ast syn::Variant) {
        self.add(&node.ident.to_string());
        syn::visit::visit_variant(self, node);
    }

    fn visit_field(&mut self, node: &'ast syn::Field) {
        if let Some(ref ident) = node.ident {
            self.add(&ident.to_string());
        }
        syn::visit::visit_field(self, node);
    }

    fn visit_pat_ident(&mut self, node: &'ast syn::PatIdent) {
        let name = node.ident.to_string();
        self.add(&name);
        self.body_locals.insert(name);
        syn::visit::visit_pat_ident(self, node);
    }

    fn visit_generic_param(&mut self, node: &'ast syn::GenericParam) {
        match node {
            syn::GenericParam::Type(tp) => {
                let name = tp.ident.to_string();
                self.add(&name);
                self.body_locals.insert(name);
            }
            syn::GenericParam::Lifetime(_) => {} // lifetimes aren't renamed
            syn::GenericParam::Const(cp) => {
                let name = cp.ident.to_string();
                self.add(&name);
                self.body_locals.insert(name);
            }
        }
        syn::visit::visit_generic_param(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        // Track whether we're in any trait impl (local or external)
        let was_external = self.in_external_trait_impl;
        if node.trait_.is_some() {
            self.in_external_trait_impl = true;
        }
        syn::visit::visit_item_impl(self, node);
        self.in_external_trait_impl = was_external;
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        // Only collect method names from INHERENT impls (no trait).
        // Trait impl methods must keep their names to match the trait definition,
        // which may be in a different file.
        if !self.in_external_trait_impl {
            let name = node.sig.ident.to_string();
            if !Self::is_pinned_fn(&node.attrs) {
                self.add(&name);
            }
        }
        // Still visit the body — local bindings inside are renameable
        syn::visit::visit_impl_item_fn(self, node);
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        // Don't collect trait method names — they must match across definition
        // and all implementations, which may be in different files. Without
        // semantic analysis, renaming trait methods causes cross-file breakage.
        // Still visit the body for local bindings.
        syn::visit::visit_trait_item_fn(self, node);
    }
}

// ---------------------------------------------------------------------------
// Phase B: Identifier renaming (mutating AST walk)
// ---------------------------------------------------------------------------

struct IdentRenamer<'a> {
    mapping: &'a HashMap<String, String>,
    /// Full cross-file registry for looking up names accessed through module paths.
    cross_file_registry: &'a HashMap<String, String>,
    local_struct_names: &'a HashSet<String>,
    local_trait_names: &'a HashSet<String>,
    local_modules: &'a HashSet<String>,
    external_crates: &'a HashSet<String>,
    crate_name: Option<&'a str>,
    in_external_trait_impl: bool,
}

impl<'a> IdentRenamer<'a> {
    fn maybe_rename(&self, ident: &mut syn::Ident) {
        let name = ident.to_string();
        if let Some(replacement) = self.mapping.get(&name) {
            *ident = syn::Ident::new(replacement, ident.span());
        }
    }

    fn maybe_rename_member(&self, member: &mut syn::Member) {
        if let syn::Member::Named(ident) = member {
            self.maybe_rename(ident);
        }
    }

    /// Rename using mapping first, then cross-file registry as fallback.
    fn maybe_rename_with_cross_file(&self, ident: &mut syn::Ident) {
        let name = ident.to_string();
        if let Some(replacement) = self.mapping.get(&name).or_else(|| self.cross_file_registry.get(&name)) {
            *ident = syn::Ident::new(replacement, ident.span());
        }
    }

    fn maybe_rename_member_with_cross_file(&self, member: &mut syn::Member) {
        if let syn::Member::Named(ident) = member {
            self.maybe_rename_with_cross_file(ident);
        }
    }

    /// Check if a trait path refers to a locally-defined trait.
    fn is_local_trait(&self, path: &syn::Path) -> bool {
        if let Some(last) = path.segments.last() {
            let name = last.ident.to_string();
            self.local_trait_names.contains(&name)
                || self.mapping.contains_key(&name)
        } else {
            false
        }
    }

    /// Rename identifiers inside a macro token stream.
    ///
    /// Since syn treats macro bodies as opaque, we walk the raw tokens
    /// and rename any `Ident` that matches our mapping. Also rewrites
    /// format string literals like `"{var:02x}"` to use renamed idents.
    fn rename_token_stream(&self, tokens: &TokenStream) -> TokenStream {
        tokens
            .clone()
            .into_iter()
            .map(|tt| match tt {
                TokenTree::Ident(ref ident) => {
                    let name = ident.to_string();
                    if let Some(replacement) = self.mapping.get(&name) {
                        TokenTree::Ident(proc_macro2::Ident::new(replacement, ident.span()))
                    } else {
                        tt
                    }
                }
                TokenTree::Group(group) => {
                    let renamed = self.rename_token_stream(&group.stream());
                    let mut new_group =
                        proc_macro2::Group::new(group.delimiter(), renamed);
                    new_group.set_span(group.span());
                    TokenTree::Group(new_group)
                }
                TokenTree::Literal(ref lit) => {
                    // Rewrite format string interpolation: {var} → {renamed_var}
                    let repr = lit.to_string();
                    if repr.starts_with('"') && repr.contains('{') {
                        let rewritten = self.rename_format_string(&repr);
                        if rewritten != repr
                            && let Ok(new_lit) = rewritten.parse::<proc_macro2::Literal>() {
                                return TokenTree::Literal(new_lit);
                            }
                    }
                    tt
                }
                _ => tt,
            })
            .collect()
    }

    /// Rewrite `{ident}` and `{ident:fmt}` patterns inside a format string literal.
    fn rename_format_string(&self, lit_repr: &str) -> String {
        // lit_repr is the token representation including quotes: "foo {bar} baz"
        let mut result = String::with_capacity(lit_repr.len());
        let mut chars = lit_repr.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '{' {
                // Collect the ident name inside { ... }
                let mut inner = String::new();
                let mut found_close = false;
                for ic in chars.by_ref() {
                    if ic == '}' {
                        found_close = true;
                        break;
                    }
                    inner.push(ic);
                }
                if found_close {
                    // Split on ':' for format spec: {var:02x} → ident="var", spec=":02x"
                    let (ident_part, spec_part) = match inner.find(':') {
                        Some(pos) => (&inner[..pos], &inner[pos..]),
                        None => (inner.as_str(), ""),
                    };
                    // Only rename if the ident part is a simple identifier in our mapping
                    if let Some(replacement) = self.mapping.get(ident_part) {
                        result.push('{');
                        result.push_str(replacement);
                        result.push_str(spec_part);
                        result.push('}');
                    } else {
                        result.push('{');
                        result.push_str(&inner);
                        result.push('}');
                    }
                } else {
                    // Unclosed brace — just emit as-is
                    result.push('{');
                    result.push_str(&inner);
                }
            } else {
                result.push(c);
            }
        }
        result
    }

    /// Check if a struct path refers to a locally-defined struct.
    fn is_local_struct_path(&self, path: &syn::Path) -> bool {
        if let Some(first) = path.segments.first() {
            let name = first.ident.to_string();
            if name == "Self" {
                return true;
            }
        }
        if path.segments.len() > 1 {
            if let Some(first) = path.segments.first() {
                let name = first.ident.to_string();
                return name == "crate" || name == "self" || name == "super"
                    || self.crate_name.is_some_and(|cn| cn == name)
                    || self.local_modules.contains(&name)
                    || self.mapping.contains_key(&name);
            }
            return false;
        }
        if let Some(last) = path.segments.last() {
            let name = last.ident.to_string();
            self.local_struct_names.contains(&name)
                || self.mapping.contains_key(&name)
        } else {
            false
        }
    }
}

impl VisitMut for IdentRenamer<'_> {
    // --- Definition sites ---

    fn visit_item_fn_mut(&mut self, node: &mut syn::ItemFn) {
        self.maybe_rename(&mut node.sig.ident);
        syn::visit_mut::visit_item_fn_mut(self, node);
    }

    fn visit_item_struct_mut(&mut self, node: &mut syn::ItemStruct) {
        self.maybe_rename(&mut node.ident);
        syn::visit_mut::visit_item_struct_mut(self, node);
    }

    fn visit_item_enum_mut(&mut self, node: &mut syn::ItemEnum) {
        self.maybe_rename(&mut node.ident);
        syn::visit_mut::visit_item_enum_mut(self, node);
    }

    fn visit_item_union_mut(&mut self, node: &mut syn::ItemUnion) {
        self.maybe_rename(&mut node.ident);
        syn::visit_mut::visit_item_union_mut(self, node);
    }

    fn visit_item_trait_mut(&mut self, node: &mut syn::ItemTrait) {
        self.maybe_rename(&mut node.ident);
        syn::visit_mut::visit_item_trait_mut(self, node);
    }

    fn visit_item_type_mut(&mut self, node: &mut syn::ItemType) {
        self.maybe_rename(&mut node.ident);
        syn::visit_mut::visit_item_type_mut(self, node);
    }

    fn visit_item_const_mut(&mut self, node: &mut syn::ItemConst) {
        self.maybe_rename(&mut node.ident);
        syn::visit_mut::visit_item_const_mut(self, node);
    }

    fn visit_item_static_mut(&mut self, node: &mut syn::ItemStatic) {
        self.maybe_rename(&mut node.ident);
        syn::visit_mut::visit_item_static_mut(self, node);
    }

    fn visit_variant_mut(&mut self, node: &mut syn::Variant) {
        self.maybe_rename(&mut node.ident);
        syn::visit_mut::visit_variant_mut(self, node);
    }

    fn visit_field_mut(&mut self, node: &mut syn::Field) {
        if let Some(ref mut ident) = node.ident {
            self.maybe_rename(ident);
        }
        syn::visit_mut::visit_field_mut(self, node);
    }

    fn visit_pat_ident_mut(&mut self, node: &mut syn::PatIdent) {
        self.maybe_rename(&mut node.ident);
        syn::visit_mut::visit_pat_ident_mut(self, node);
    }

    fn visit_item_impl_mut(&mut self, node: &mut syn::ItemImpl) {
        // Track whether we're in any trait impl
        let was_external = self.in_external_trait_impl;
        if node.trait_.is_some() {
            self.in_external_trait_impl = true;
        }
        syn::visit_mut::visit_item_impl_mut(self, node);
        self.in_external_trait_impl = was_external;
    }

    fn visit_impl_item_fn_mut(&mut self, node: &mut syn::ImplItemFn) {
        // Don't rename method names in any trait impl — trait methods must
        // match the trait definition, which may be in a different file.
        if !self.in_external_trait_impl {
            self.maybe_rename(&mut node.sig.ident);
        }
        syn::visit_mut::visit_impl_item_fn_mut(self, node);
    }

    fn visit_trait_item_fn_mut(&mut self, node: &mut syn::TraitItemFn) {
        self.maybe_rename(&mut node.sig.ident);
        syn::visit_mut::visit_trait_item_fn_mut(self, node);
    }

    fn visit_generic_param_mut(&mut self, node: &mut syn::GenericParam) {
        match node {
            syn::GenericParam::Type(tp) => self.maybe_rename(&mut tp.ident),
            syn::GenericParam::Const(cp) => self.maybe_rename(&mut cp.ident),
            _ => {}
        }
        syn::visit_mut::visit_generic_param_mut(self, node);
    }

    // --- Usage sites ---

    fn visit_expr_field_mut(&mut self, node: &mut syn::ExprField) {
        // Use cross-file registry for field access — fields may be defined
        // in a different file's struct definition.
        self.maybe_rename_member_with_cross_file(&mut node.member);
        syn::visit_mut::visit_expr_field_mut(self, node);
    }

    fn visit_expr_method_call_mut(&mut self, node: &mut syn::ExprMethodCall) {
        // DON'T rename method call names — without type info we can't tell
        // if `.method()` is on a local type or an external one. Methods like
        // .map_err(), .call(), .error(), .stdout() would break.
        // The method name in the definition site (visit_impl_item_fn_mut) handles
        // renaming for local methods. The call sites will still use the original
        // name... which means local method calls won't be renamed either.
        // This is a trade-off: correctness over maximum obfuscation.
        //
        // HOWEVER: we still need to visit children (the receiver and arguments).
        syn::visit_mut::visit_expr_method_call_mut(self, node);
    }

    fn visit_field_value_mut(&mut self, node: &mut syn::FieldValue) {
        // Struct literal field names — only rename if we're confident
        // the struct is local. We check this at the ExprStruct level.
        // Don't rename here by default — ExprStruct handler will manage it.
        syn::visit_mut::visit_field_value_mut(self, node);
    }

    fn visit_field_pat_mut(&mut self, node: &mut syn::FieldPat) {
        // Same logic as field_value — conservative, only rename if local.
        self.maybe_rename_member(&mut node.member);
        syn::visit_mut::visit_field_pat_mut(self, node);
    }

    fn visit_expr_struct_mut(&mut self, node: &mut syn::ExprStruct) {
        let is_local = self.is_local_struct_path(&node.path);

        // Rename the struct path itself if it's local
        if is_local {
            rename_path_local(&mut node.path, self.mapping, self.cross_file_registry, self.local_modules, self.external_crates, self.crate_name);
        }

        // Rename field names if the struct is local (using cross-file for cross-module structs)
        if is_local {
            for field in &mut node.fields {
                self.maybe_rename_member_with_cross_file(&mut field.member);
            }
        }

        // Visit field value expressions (they may contain renameable idents)
        for field in &mut node.fields {
            syn::visit_mut::visit_expr_mut(self, &mut field.expr);
        }

        // Visit rest (..) if present
        if let Some(ref mut rest) = node.rest {
            syn::visit_mut::visit_expr_mut(self, rest);
        }
    }

    // --- Attributes: don't rename inside them ---

    fn visit_attribute_mut(&mut self, node: &mut syn::Attribute) {
        // Special-case: thiserror #[error("...")] contains field name interpolations
        // that need renaming to match renamed struct fields.
        if node.path().is_ident("error")
            && let syn::Meta::List(ref mut meta_list) = node.meta {
                meta_list.tokens = self.rename_token_stream(&meta_list.tokens);
            }
        // Skip all other attributes — they reference external macro/derive names.
    }

    // --- Use statements (UseTree is a separate AST node from Path) ---

    fn visit_use_tree_mut(&mut self, node: &mut syn::UseTree) {
        match node {
            syn::UseTree::Name(name) => {
                // Only rename if it's an item (type/fn/const), not a module name.
                // Module names map to filesystem paths and must stay as-is.
                let ident_str = name.ident.to_string();
                if !self.local_modules.contains(&ident_str) {
                    self.maybe_rename(&mut name.ident);
                }
            }
            syn::UseTree::Rename(rename) => {
                let ident_str = rename.ident.to_string();
                if !self.local_modules.contains(&ident_str) {
                    self.maybe_rename(&mut rename.ident);
                }
            }
            _ => {}
        }
        syn::visit_mut::visit_use_tree_mut(self, node);
    }

    // --- Macro bodies (opaque token streams) ---

    fn visit_macro_mut(&mut self, node: &mut syn::Macro) {
        // Rename identifiers inside macro token streams (json!{}, format!{}, etc.)
        node.tokens = self.rename_token_stream(&node.tokens);
        // Don't call the default visitor — we've already handled the tokens
    }

    // --- Path references ---

    fn visit_path_mut(&mut self, node: &mut syn::Path) {
        rename_path_local(node, self.mapping, self.cross_file_registry, self.local_modules, self.external_crates, self.crate_name);
        syn::visit_mut::visit_path_mut(self, node);
    }
}

/// Collect imported module/item names from `use` trees that are internal.
///
/// Recognizes `use crate::...`, `use self::...`, `use super::...`, and
/// `use <crate_name>::...` (the crate's own name from Cargo.toml).
fn collect_use_modules(tree: &syn::UseTree, modules: &mut HashSet<String>, imported_items: &mut HashSet<String>, crate_name: Option<&str>) {
    match tree {
        syn::UseTree::Path(path) => {
            let first = path.ident.to_string();
            let is_internal = first == "crate" || first == "self" || first == "super"
                || crate_name.is_some_and(|cn| cn == first);
            if is_internal {
                collect_use_leaf(&path.tree, modules, imported_items);
            }
        }
        syn::UseTree::Name(name) => {
            modules.insert(name.ident.to_string());
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_use_modules(item, modules, imported_items, crate_name);
            }
        }
        _ => {}
    }
}

/// Collect MODULE names from an internal use path.
///
/// Path segments and direct Name leaves (could be module imports) are added.
/// Items inside groups (e.g., `{ObfuscationPass, PassContext}`) are NOT modules.
fn collect_use_leaf(tree: &syn::UseTree, modules: &mut HashSet<String>, imported_items: &mut HashSet<String>) {
    match tree {
        syn::UseTree::Path(path) => {
            modules.insert(path.ident.to_string());
            collect_use_leaf(&path.tree, modules, imported_items);
        }
        syn::UseTree::Name(name) => {
            // Direct leaf — could be a module import (`use crate::key;`)
            // Add to modules so `key::derive_subkey` is recognized as local
            modules.insert(name.ident.to_string());
            // Also add as imported item for cross-file registry lookups
            imported_items.insert(name.ident.to_string());
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                match item {
                    syn::UseTree::Path(p) => {
                        modules.insert(p.ident.to_string());
                        collect_use_leaf(&p.tree, modules, imported_items);
                    }
                    syn::UseTree::Name(name) => {
                        // Item inside group = imported type/function
                        imported_items.insert(name.ident.to_string());
                    }
                    syn::UseTree::Rename(rename) => {
                        imported_items.insert(rename.rename.to_string());
                    }
                    _ => {}
                }
            }
        }
        syn::UseTree::Rename(rename) => {
            modules.insert(rename.rename.to_string());
        }
        syn::UseTree::Glob(_) => {}
    }
}

/// Rename a path's last segment if it's a local reference.
///
/// Single-segment paths (e.g., `Warrior`, `my_function`) are local.
/// Multi-segment paths starting with `crate::`, `self::`, `super::`, or a local
/// module name are internal. Other multi-segment paths are external — don't touch.
fn rename_path_local(
    path: &mut syn::Path,
    mapping: &HashMap<String, String>,
    cross_file_registry: &HashMap<String, String>,
    local_modules: &HashSet<String>,
    external_crates: &HashSet<String>,
    crate_name: Option<&str>,
) {
    let should_rename = if path.segments.len() == 1 {
        // Single-segment: rename unless it's an external crate name itself
        let name = path.segments[0].ident.to_string();
        !external_crates.contains(&name)
    } else if let Some(first) = path.segments.first() {
        let name = first.ident.to_string();
        // Definitively external — don't touch
        if external_crates.contains(&name) {
            false
        } else {
            // Internal if: crate, self, super, own crate name, known local module,
            // or the first segment itself is a renamed local identifier (e.g., ApateError::KeyNotFound)
            name == "crate" || name == "self" || name == "super"
                || crate_name.is_some_and(|cn| cn == name)
                || local_modules.contains(&name)
                || mapping.contains_key(&name)
        }
    } else {
        false
    };

    if should_rename {
        if path.segments.len() == 1 {
            // Single-segment: rename if in mapping
            let seg = &mut path.segments[0];
            let name = seg.ident.to_string();
            if let Some(replacement) = mapping.get(&name) {
                seg.ident = syn::Ident::new(replacement, seg.ident.span());
            }
        } else {
            // Multi-segment internal path: rename all non-module, non-keyword segments.
            // e.g., `ApateError::KeyNotFound` → rename both `ApateError` and `KeyNotFound`
            //        `crate::error::ApateError` → skip `crate`, skip `error` (module), rename `ApateError`
            for seg in &mut path.segments {
                let name = seg.ident.to_string();
                if name == "crate" || name == "self" || name == "super" {
                    continue;
                }
                if crate_name.is_some_and(|cn| cn == name) {
                    continue;
                }
                if local_modules.contains(&name) {
                    continue;
                }
                // Check local mapping first, then cross-file registry
                if let Some(replacement) = mapping.get(&name).or_else(|| cross_file_registry.get(&name)) {
                    seg.ident = syn::Ident::new(replacement, seg.ident.span());
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Static blocklist
// ---------------------------------------------------------------------------

pub fn static_blocklist() -> HashSet<String> {
    let items: &[&str] = &[
        // Keywords & special idents
        "self", "Self", "super", "crate", "main",
        // Primitives
        "bool", "char", "str",
        "i8", "i16", "i32", "i64", "i128", "isize",
        "u8", "u16", "u32", "u64", "u128", "usize",
        "f32", "f64",
        // Core types
        "String", "Vec", "Option", "Result", "Box", "Rc", "Arc",
        "HashMap", "HashSet", "BTreeMap", "BTreeSet", "PhantomData",
        "Some", "None", "Ok", "Err", "true", "false",
        // Std trait names (appear in derives, bounds, impl blocks)
        "Copy", "Clone", "Debug", "Display", "Default", "Send", "Sync",
        "Sized", "Unpin", "Drop", "Fn", "FnMut", "FnOnce", "Future",
        "Iterator", "IntoIterator", "From", "Into", "TryFrom", "TryInto",
        "AsRef", "AsMut", "ToOwned", "ToString", "PartialEq", "Eq",
        "PartialOrd", "Ord", "Hash", "Add", "Sub", "Mul", "Div",
        "Neg", "Not", "Index", "IndexMut", "Deref", "DerefMut",
        "Borrow", "BorrowMut", "Read", "Write", "Seek", "Error",
        // Std trait method names
        "fmt", "clone", "clone_from", "drop", "deref", "deref_mut",
        "index", "index_mut", "into", "from", "try_from", "try_into",
        "as_ref", "as_mut", "borrow", "borrow_mut", "to_string",
        "to_owned", "into_iter", "next", "size_hint", "eq", "ne",
        "partial_cmp", "cmp", "hash", "default", "new", "with_capacity",
        "len", "is_empty", "iter", "iter_mut", "push", "pop", "insert",
        "remove", "contains", "get", "unwrap", "expect", "map",
        "and_then", "or_else", "ok", "err", "write", "read", "flush", "seek",
        // Macros
        "println", "eprintln", "format", "vec", "panic", "assert",
        "assert_eq", "assert_ne", "dbg", "todo", "unimplemented",
        "cfg", "derive", "allow", "warn", "deny", "test", "bench",
        "include", "include_str", "include_bytes", "env", "concat",
        "stringify", "writeln",
        // Attribute idents and derive helper names
        "inline", "must_use", "doc", "feature", "no_mangle", "repr", "path",
        "source", "transparent", "from", "error",
        // Common format/conversion
        "as", "ref", "mut", "move", "return", "break", "continue",
        "if", "else", "match", "for", "while", "loop", "in",
        "let", "const", "static", "fn", "struct", "enum", "trait",
        "impl", "type", "mod", "use", "pub", "where", "async", "await",
        "dyn", "unsafe", "extern",
    ];
    items.iter().map(|s| s.to_string()).collect()
}
