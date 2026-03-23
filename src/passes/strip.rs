use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};

use crate::error::{ApateError, Result};
use crate::passes::{ObfuscationPass, PassContext, PassRecord};

/// Strip pass — removes doc comments and stores the original source for roundtrip.
///
/// Regular `//` and `/* */` comments are already discarded by `syn::parse_file()`.
/// This pass handles:
/// 1. Storing the original source text (with all comments) for byte-for-byte decrypt
/// 2. Stripping doc attributes (`///`, `//!`, `#[doc = "..."]`) from the AST
pub struct StripPass;

#[derive(Debug, Serialize, Deserialize)]
struct StripData {
    /// Base64-encoded original source text.
    original_source: String,
}

impl ObfuscationPass for StripPass {
    fn name(&self) -> &'static str {
        "strip"
    }

    fn encrypt(
        &self,
        ast: &mut syn::File,
        context: &mut PassContext,
    ) -> Result<PassRecord> {
        let original = context.original_source.as_ref().ok_or_else(|| {
            ApateError::PassFailed {
                pass: "strip".into(),
                reason: "original_source not set in context".into(),
            }
        })?;

        let data = StripData {
            original_source: BASE64.encode(original.as_bytes()),
        };

        // Strip inner doc attributes (#![doc = "..."])
        ast.attrs.retain(|attr| !is_doc_attr(attr));

        // Suppress style lints that fire on obfuscated identifiers
        let lint_attr: syn::Attribute = syn::parse_quote! {
            #![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]
        };
        ast.attrs.insert(0, lint_attr);

        // Strip doc attributes from all top-level items
        strip_doc_attrs_from_items(&mut ast.items);

        Ok(PassRecord {
            pass_name: self.name().to_string(),
            data: serde_json::to_value(data).expect("StripData serializes"),
        })
    }

    fn decrypt(
        &self,
        _ast: &mut syn::File,
        _record: &PassRecord,
        _context: &PassContext,
    ) -> Result<()> {
        // No-op at the AST level — the pipeline handles source restoration
        // by extracting original_source from the strip pass record.
        Ok(())
    }
}

/// Extract the original source text from a strip pass record.
pub fn extract_original_source(record: &PassRecord) -> Result<String> {
    let data: StripData =
        serde_json::from_value(record.data.clone()).map_err(|e| ApateError::PassFailed {
            pass: "strip".into(),
            reason: format!("failed to deserialize strip data: {e}"),
        })?;
    let bytes = BASE64.decode(&data.original_source).map_err(|e| {
        ApateError::PassFailed {
            pass: "strip".into(),
            reason: format!("failed to decode base64 original source: {e}"),
        }
    })?;
    String::from_utf8(bytes).map_err(|e| ApateError::PassFailed {
        pass: "strip".into(),
        reason: format!("original source is not valid UTF-8: {e}"),
    })
}

/// Check if an attribute is a doc attribute.
fn is_doc_attr(attr: &syn::Attribute) -> bool {
    attr.path().is_ident("doc")
}

/// Recursively strip doc attributes from items and their nested contents.
fn strip_doc_attrs_from_items(items: &mut [syn::Item]) {
    for item in items.iter_mut() {
        strip_doc_attrs_from_item(item);
    }
}

fn strip_doc_attrs_from_item(item: &mut syn::Item) {
    // Strip doc attrs from the item itself
    if let Some(attrs) = get_attrs_mut(item) {
        attrs.retain(|attr| !is_doc_attr(attr));
    }

    // Recurse into nested items (impl blocks, trait defs, modules, etc.)
    match item {
        syn::Item::Impl(impl_item) => {
            for inner in &mut impl_item.items {
                strip_doc_attrs_from_impl_item(inner);
            }
        }
        syn::Item::Trait(trait_item) => {
            for inner in &mut trait_item.items {
                strip_doc_attrs_from_trait_item(inner);
            }
        }
        syn::Item::Mod(mod_item) => {
            if let Some((_, ref mut items)) = mod_item.content {
                strip_doc_attrs_from_items(items);
            }
        }
        syn::Item::Enum(enum_item) => {
            for variant in &mut enum_item.variants {
                variant.attrs.retain(|a| !is_doc_attr(a));
            }
        }
        syn::Item::Struct(struct_item) => {
            strip_doc_attrs_from_fields(&mut struct_item.fields);
        }
        _ => {}
    }
}

fn strip_doc_attrs_from_impl_item(item: &mut syn::ImplItem) {
    match item {
        syn::ImplItem::Fn(m) => m.attrs.retain(|a| !is_doc_attr(a)),
        syn::ImplItem::Const(c) => c.attrs.retain(|a| !is_doc_attr(a)),
        syn::ImplItem::Type(t) => t.attrs.retain(|a| !is_doc_attr(a)),
        _ => {}
    }
}

fn strip_doc_attrs_from_trait_item(item: &mut syn::TraitItem) {
    match item {
        syn::TraitItem::Fn(m) => m.attrs.retain(|a| !is_doc_attr(a)),
        syn::TraitItem::Const(c) => c.attrs.retain(|a| !is_doc_attr(a)),
        syn::TraitItem::Type(t) => t.attrs.retain(|a| !is_doc_attr(a)),
        _ => {}
    }
}

fn strip_doc_attrs_from_fields(fields: &mut syn::Fields) {
    match fields {
        syn::Fields::Named(named) => {
            for field in &mut named.named {
                field.attrs.retain(|a| !is_doc_attr(a));
            }
        }
        syn::Fields::Unnamed(unnamed) => {
            for field in &mut unnamed.unnamed {
                field.attrs.retain(|a| !is_doc_attr(a));
            }
        }
        syn::Fields::Unit => {}
    }
}

/// Get mutable reference to an item's attributes.
fn get_attrs_mut(item: &mut syn::Item) -> Option<&mut Vec<syn::Attribute>> {
    Some(match item {
        syn::Item::Const(i) => &mut i.attrs,
        syn::Item::Enum(i) => &mut i.attrs,
        syn::Item::ExternCrate(i) => &mut i.attrs,
        syn::Item::Fn(i) => &mut i.attrs,
        syn::Item::ForeignMod(i) => &mut i.attrs,
        syn::Item::Impl(i) => &mut i.attrs,
        syn::Item::Macro(i) => &mut i.attrs,
        syn::Item::Mod(i) => &mut i.attrs,
        syn::Item::Static(i) => &mut i.attrs,
        syn::Item::Struct(i) => &mut i.attrs,
        syn::Item::Trait(i) => &mut i.attrs,
        syn::Item::TraitAlias(i) => &mut i.attrs,
        syn::Item::Type(i) => &mut i.attrs,
        syn::Item::Union(i) => &mut i.attrs,
        syn::Item::Use(i) => &mut i.attrs,
        _ => return None,
    })
}
