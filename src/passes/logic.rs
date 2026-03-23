use serde::{Deserialize, Serialize};
use syn::visit_mut::VisitMut;

use crate::error::{ApateError, Result};
use crate::passes::{ObfuscationPass, PassContext, PassRecord};
use crate::utils::crypto;

/// Logic obfuscation pass — transforms control flow into semantically equivalent
/// but harder-to-read forms.
///
/// Current transform: `if/else` → `match` on `true`/`false`.
/// Future: constant folding reversal, boolean→bitwise, loop unrolling.
pub struct LogicPass;

#[derive(Debug, Serialize, Deserialize)]
struct LogicData {
    /// Number of if→match transforms applied (for counting during decrypt).
    if_to_match_count: usize,
}

impl ObfuscationPass for LogicPass {
    fn name(&self) -> &'static str {
        "logic"
    }

    fn encrypt(
        &self,
        ast: &mut syn::File,
        context: &mut PassContext,
    ) -> Result<PassRecord> {
        let mut transformer = LogicTransformer {
            hmac_key: context.hmac_key.clone(),
            counter: 0,
            transform_count: 0,
        };
        transformer.visit_file_mut(ast);

        let data = LogicData {
            if_to_match_count: transformer.transform_count,
        };

        Ok(PassRecord {
            pass_name: self.name().to_string(),
            data: serde_json::to_value(data).expect("LogicData serializes"),
        })
    }

    fn decrypt(
        &self,
        ast: &mut syn::File,
        record: &PassRecord,
        _context: &PassContext,
    ) -> Result<()> {
        let data: LogicData =
            serde_json::from_value(record.data.clone()).map_err(|e| ApateError::PassFailed {
                pass: "logic".into(),
                reason: format!("failed to deserialize logic data: {e}"),
            })?;

        let mut reverser = LogicReverser {
            remaining: data.if_to_match_count,
        };
        reverser.visit_file_mut(ast);

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Encrypt: if/else → match on true/false
// ---------------------------------------------------------------------------

struct LogicTransformer {
    hmac_key: Vec<u8>,
    counter: usize,
    transform_count: usize,
}

impl LogicTransformer {
    /// Decide whether to transform based on HMAC of counter (~70% chance).
    fn should_transform(&self) -> bool {
        let hash = crypto::hmac_sha256(
            &self.hmac_key,
            format!("if_to_match_{}", self.counter).as_bytes(),
        );
        hash[0] < 179
    }

    fn try_transform(&mut self, node: &mut syn::Expr) {
        let syn::Expr::If(expr_if) = node else {
            return;
        };

        // Skip if-let expressions and let-chains (e.g., `if let Some(x) = y && let Some(z) = w`)
        if contains_let(&expr_if.cond) {
            return;
        }

        if !self.should_transform() {
            self.counter += 1;
            return;
        }

        let cond = &expr_if.cond;
        let then_block = &expr_if.then_branch;

        let match_expr: syn::Expr = if let Some((_, else_branch)) = &expr_if.else_branch {
            syn::parse_quote! {
                match #cond {
                    true => #then_block,
                    false => { #else_branch },
                }
            }
        } else {
            syn::parse_quote! {
                match #cond {
                    true => #then_block,
                    false => {},
                }
            }
        };

        *node = match_expr;
        self.counter += 1;
        self.transform_count += 1;
    }
}

impl VisitMut for LogicTransformer {
    fn visit_expr_mut(&mut self, node: &mut syn::Expr) {
        // Recurse first so inner expressions are transformed bottom-up
        syn::visit_mut::visit_expr_mut(self, node);
        self.try_transform(node);
    }
}

// ---------------------------------------------------------------------------
// Decrypt: match on true/false → if/else
// ---------------------------------------------------------------------------

struct LogicReverser {
    remaining: usize,
}

impl LogicReverser {
    /// Check if a match expression is our true/false pattern.
    fn is_bool_match(expr: &syn::Expr) -> bool {
        let syn::Expr::Match(expr_match) = expr else {
            return false;
        };
        if expr_match.arms.len() != 2 {
            return false;
        }
        let has_true = expr_match.arms.iter().any(|arm| is_bool_pat(&arm.pat, true));
        let has_false = expr_match.arms.iter().any(|arm| is_bool_pat(&arm.pat, false));
        has_true && has_false
    }

    /// Reconstruct an if/else directly from the match AST.
    fn match_to_if(expr: &syn::Expr) -> Option<syn::Expr> {
        let syn::Expr::Match(expr_match) = expr else {
            return None;
        };

        let cond = &expr_match.expr;
        let true_arm = expr_match.arms.iter().find(|a| is_bool_pat(&a.pat, true))?;
        let false_arm = expr_match.arms.iter().find(|a| is_bool_pat(&a.pat, false))?;

        let then_block = expr_to_block(&true_arm.body);
        let has_else = !is_empty_block(&false_arm.body);

        if has_else {
            let else_block = expr_to_block(&false_arm.body);
            Some(syn::parse_quote! { if #cond #then_block else #else_block })
        } else {
            Some(syn::parse_quote! { if #cond #then_block })
        }
    }
}

impl VisitMut for LogicReverser {
    fn visit_expr_mut(&mut self, node: &mut syn::Expr) {
        // Recurse first
        syn::visit_mut::visit_expr_mut(self, node);

        if self.remaining == 0 {
            return;
        }

        if Self::is_bool_match(node)
            && let Some(original) = Self::match_to_if(node)
        {
            *node = original;
            self.remaining -= 1;
        }
    }
}

/// Extract a Block from an expression, or wrap it in one.
fn expr_to_block(expr: &syn::Expr) -> syn::Block {
    if let syn::Expr::Block(eb) = expr {
        eb.block.clone()
    } else {
        syn::parse_quote! { { #expr } }
    }
}

/// Check if an expression is an empty block `{}`.
fn is_empty_block(expr: &syn::Expr) -> bool {
    if let syn::Expr::Block(block) = expr {
        block.block.stmts.is_empty()
    } else {
        false
    }
}

/// Check if an expression contains any `let` (including inside `&&` chains).
fn contains_let(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Let(_) => true,
        syn::Expr::Binary(bin) if matches!(bin.op, syn::BinOp::And(_)) => {
            contains_let(&bin.left) || contains_let(&bin.right)
        }
        _ => false,
    }
}

/// Check if a pattern is a literal bool (true or false).
fn is_bool_pat(pat: &syn::Pat, value: bool) -> bool {
    use quote::ToTokens;
    let tokens = pat.to_token_stream().to_string();
    if value {
        tokens.trim() == "true"
    } else {
        tokens.trim() == "false"
    }
}
