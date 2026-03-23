use std::collections::{BTreeSet, HashMap};

use proc_macro2::{TokenStream, TokenTree};
use serde::{Deserialize, Serialize};
use syn::visit_mut::VisitMut;

use crate::error::{ApateError, Result};
use crate::passes::{ObfuscationPass, PassContext, PassRecord};
use crate::passes::rename;
use crate::utils::{crypto, homoglyphs};

/// Homoglyph pass — replaces ASCII chars in identifiers with Cyrillic lookalikes.
pub struct HomoglyphPass;

#[derive(Debug, Serialize, Deserialize)]
struct HomoglyphData {
    /// Per-identifier substitution records: ident → [(char_position, original, replacement)]
    substitutions: HashMap<String, Vec<(usize, char, char)>>,
    /// Whether Apate inserted the #![allow(...)] attribute (vs it already existing).
    inserted_allow: bool,
}

impl ObfuscationPass for HomoglyphPass {
    fn name(&self) -> &'static str {
        "homoglyph"
    }

    fn encrypt(
        &self,
        ast: &mut syn::File,
        context: &mut PassContext,
    ) -> Result<PassRecord> {
        // Only homoglyph identifiers that were confirmed local (renamed by the rename pass).
        // This prevents corrupting external crate types, methods, and field names.
        let renameable_idents: BTreeSet<String> = context
            .ident_registry
            .values()
            .cloned()
            .collect();

        let blocklist = rename::static_blocklist();
        let mut substitutions: HashMap<String, Vec<(usize, char, char)>> = HashMap::new();
        let mut ident_mapping: HashMap<String, String> = HashMap::new();

        for name in &renameable_idents {
            if blocklist.contains(name) {
                continue;
            }
            let hash = crypto::hmac_sha256(&context.hmac_key, name.as_bytes());

            // ~39% chance of applying homoglyphs
            if hash[0] >= 100 {
                continue;
            }

            let eligible = homoglyphs::eligible_positions(name);
            if eligible.is_empty() {
                continue;
            }

            let num_replacements = 1 + (hash[1] as usize % 3).min(eligible.len());
            let mut chars: Vec<char> = name.chars().collect();
            let mut subs = Vec::new();

            for i in 0..num_replacements {
                let pos_idx = hash[2 + i] as usize % eligible.len();
                let char_pos = eligible[pos_idx];

                // Find the actual char index (eligible_positions returns byte indices)
                if let Some(original_char) = chars.get(char_pos).copied()
                    && let Some(replacement) = homoglyphs::ascii_to_homoglyph(original_char)
                {
                    chars[char_pos] = replacement;
                    subs.push((char_pos, original_char, replacement));
                }
            }

            if !subs.is_empty() {
                let new_name: String = chars.into_iter().collect();
                substitutions.insert(name.clone(), subs);
                ident_mapping.insert(name.clone(), new_name);
            }
        }

        // Walk AST and replace identifiers
        let mut renamer = HomoglyphRenamer {
            mapping: &ident_mapping,
        };
        renamer.visit_file_mut(ast);

        // Check if allow attribute already exists before inserting
        let already_has_allow = ast.attrs.iter().any(is_homoglyph_allow);
        let inserted_allow = if !already_has_allow {
            // Insert #![allow(mixed_script_confusables, uncommon_codepoints, confusable_idents)]
            let attr = syn::parse_quote! {
                #![allow(mixed_script_confusables, uncommon_codepoints, confusable_idents, non_snake_case, non_upper_case_globals)]
            };
            ast.attrs.insert(0, attr);
            true
        } else {
            false
        };

        let data = HomoglyphData {
            substitutions,
            inserted_allow,
        };

        Ok(PassRecord {
            pass_name: self.name().to_string(),
            data: serde_json::to_value(data).expect("HomoglyphData serializes"),
        })
    }

    fn decrypt(
        &self,
        ast: &mut syn::File,
        record: &PassRecord,
        _context: &PassContext,
    ) -> Result<()> {
        let data: HomoglyphData =
            serde_json::from_value(record.data.clone()).map_err(|e| ApateError::PassFailed {
                pass: "homoglyph".into(),
                reason: format!("failed to deserialize homoglyph data: {e}"),
            })?;

        // Build reverse mapping: homoglyphed → original
        let mut reverse_mapping: HashMap<String, String> = HashMap::new();
        for (original, subs) in &data.substitutions {
            let mut chars: Vec<char> = original.chars().collect();
            for &(pos, _orig, replacement) in subs {
                if pos < chars.len() {
                    chars[pos] = replacement;
                }
            }
            let homoglyphed: String = chars.into_iter().collect();
            reverse_mapping.insert(homoglyphed, original.clone());
        }

        let mut renamer = HomoglyphRenamer {
            mapping: &reverse_mapping,
        };
        renamer.visit_file_mut(ast);

        // Remove the allow attribute only if Apate inserted it
        if data.inserted_allow {
            ast.attrs.retain(|a| !is_homoglyph_allow(a));
        }

        Ok(())
    }
}

/// Check if an attribute is our specific allow attribute.
fn is_homoglyph_allow(attr: &syn::Attribute) -> bool {
    if !attr.path().is_ident("allow") {
        return false;
    }
    // Check if it contains mixed_script_confusables
    use quote::ToTokens;
    let tokens = attr.meta.to_token_stream().to_string();
    tokens.contains("mixed_script_confusables")
}

// ---------------------------------------------------------------------------
// Identifier replacement (same pattern as rename pass)
// ---------------------------------------------------------------------------

struct HomoglyphRenamer<'a> {
    mapping: &'a HashMap<String, String>,
}

impl<'a> HomoglyphRenamer<'a> {
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
                _ => tt,
            })
            .collect()
    }
}

impl VisitMut for HomoglyphRenamer<'_> {
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

    fn visit_macro_mut(&mut self, node: &mut syn::Macro) {
        node.tokens = self.rename_token_stream(&node.tokens);
    }

    fn visit_impl_item_fn_mut(&mut self, node: &mut syn::ImplItemFn) {
        self.maybe_rename(&mut node.sig.ident);
        syn::visit_mut::visit_impl_item_fn_mut(self, node);
    }

    fn visit_trait_item_fn_mut(&mut self, node: &mut syn::TraitItemFn) {
        self.maybe_rename(&mut node.sig.ident);
        syn::visit_mut::visit_trait_item_fn_mut(self, node);
    }

    fn visit_expr_field_mut(&mut self, node: &mut syn::ExprField) {
        self.maybe_rename_member(&mut node.member);
        syn::visit_mut::visit_expr_field_mut(self, node);
    }

    fn visit_expr_method_call_mut(&mut self, node: &mut syn::ExprMethodCall) {
        self.maybe_rename(&mut node.method);
        syn::visit_mut::visit_expr_method_call_mut(self, node);
    }

    fn visit_field_value_mut(&mut self, node: &mut syn::FieldValue) {
        self.maybe_rename_member(&mut node.member);
        syn::visit_mut::visit_field_value_mut(self, node);
    }

    fn visit_field_pat_mut(&mut self, node: &mut syn::FieldPat) {
        self.maybe_rename_member(&mut node.member);
        syn::visit_mut::visit_field_pat_mut(self, node);
    }

    fn visit_use_tree_mut(&mut self, node: &mut syn::UseTree) {
        match node {
            syn::UseTree::Name(name) => self.maybe_rename(&mut name.ident),
            syn::UseTree::Rename(rename) => self.maybe_rename(&mut rename.ident),
            _ => {}
        }
        syn::visit_mut::visit_use_tree_mut(self, node);
    }

    fn visit_path_mut(&mut self, node: &mut syn::Path) {
        // The homoglyph mapping only contains HMAC-renamed local identifiers.
        // These won't collide with external crate names, so it's safe to
        // check every segment of any path.
        for seg in &mut node.segments {
            self.maybe_rename(&mut seg.ident);
        }
        syn::visit_mut::visit_path_mut(self, node);
    }

    fn visit_attribute_mut(&mut self, _node: &mut syn::Attribute) {
        // Skip homoglyphing inside attributes
    }
}
