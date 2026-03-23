use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};

use crate::error::{ApateError, Result};
use crate::passes::{ObfuscationPass, PassContext, PassRecord};

/// Reorder pass — deterministically shuffles top-level items.
pub struct ReorderPass;

#[derive(Debug, Serialize, Deserialize)]
struct ReorderData {
    /// Permutation vector: `permutation[new_index] = original_index`.
    permutation: Vec<usize>,
}

impl ObfuscationPass for ReorderPass {
    fn name(&self) -> &'static str {
        "reorder"
    }

    fn encrypt(
        &self,
        ast: &mut syn::File,
        context: &mut PassContext,
    ) -> Result<PassRecord> {
        let items = std::mem::take(&mut ast.items);

        // Separate pinned items (must stay at top) from shuffleable items
        let mut pinned = Vec::new();
        let mut shuffleable = Vec::new();
        let mut original_indices = Vec::new();

        for (i, item) in items.into_iter().enumerate() {
            if is_pinned(&item) {
                pinned.push(item);
            } else {
                original_indices.push(i);
                shuffleable.push(item);
            }
        }

        // Generate deterministic permutation via Fisher-Yates shuffle
        let mut index_order: Vec<usize> = (0..shuffleable.len()).collect();
        index_order.shuffle(&mut context.rng);

        // Apply permutation
        let mut shuffled: Vec<syn::Item> = Vec::with_capacity(shuffleable.len());
        for &idx in &index_order {
            shuffled.push(shuffleable[idx].clone());
        }

        // Build the permutation record: permutation[new_pos] = original_pos_in_shuffleable
        let permutation = index_order;

        // Recombine: pinned items first, then shuffled
        ast.items = pinned;
        ast.items.extend(shuffled);

        let data = ReorderData { permutation };

        Ok(PassRecord {
            pass_name: self.name().to_string(),
            data: serde_json::to_value(data).expect("ReorderData serializes"),
        })
    }

    fn decrypt(
        &self,
        ast: &mut syn::File,
        record: &PassRecord,
        _context: &PassContext,
    ) -> Result<()> {
        let data: ReorderData =
            serde_json::from_value(record.data.clone()).map_err(|e| ApateError::PassFailed {
                pass: "reorder".into(),
                reason: format!("failed to deserialize reorder data: {e}"),
            })?;

        let items = std::mem::take(&mut ast.items);

        // Separate pinned from shuffled (same logic as encrypt)
        let mut pinned = Vec::new();
        let mut shuffled = Vec::new();

        for item in items {
            if is_pinned(&item) {
                pinned.push(item);
            } else {
                shuffled.push(item);
            }
        }

        // Apply inverse permutation
        // permutation[new_pos] = original_pos means:
        // to get original order, place shuffled[new_pos] at permutation[new_pos]
        let mut restored: Vec<Option<syn::Item>> = vec![None; shuffled.len()];
        for (new_pos, &orig_pos) in data.permutation.iter().enumerate() {
            if new_pos < shuffled.len() && orig_pos < restored.len() {
                restored[orig_pos] = Some(shuffled[new_pos].clone());
            }
        }

        let restored: Vec<syn::Item> = restored.into_iter().flatten().collect();

        // Recombine: pinned first, then restored original order
        ast.items = pinned;
        ast.items.extend(restored);

        Ok(())
    }
}

/// Determine if an item should be pinned (not shuffled).
///
/// Pinned items: extern crate, mod declarations, items with #[macro_use],
/// use items with #[macro_use], mod with #[path = "..."].
fn is_pinned(item: &syn::Item) -> bool {
    match item {
        syn::Item::ExternCrate(_) => true,
        syn::Item::Mod(_) => true,
        _ => has_macro_use(item),
    }
}

/// Check if an item has the #[macro_use] attribute.
fn has_macro_use(item: &syn::Item) -> bool {
    let attrs = match item {
        syn::Item::Use(u) => &u.attrs,
        syn::Item::ExternCrate(e) => &e.attrs,
        syn::Item::Mod(m) => &m.attrs,
        syn::Item::Fn(f) => &f.attrs,
        syn::Item::Struct(s) => &s.attrs,
        syn::Item::Enum(e) => &e.attrs,
        syn::Item::Impl(i) => &i.attrs,
        syn::Item::Trait(t) => &t.attrs,
        syn::Item::Const(c) => &c.attrs,
        syn::Item::Static(s) => &s.attrs,
        syn::Item::Type(t) => &t.attrs,
        _ => return false,
    };
    attrs.iter().any(|a| a.path().is_ident("macro_use"))
}
