use serde::{Deserialize, Serialize};
use syn::visit_mut::VisitMut;

use crate::error::{ApateError, Result};
use crate::passes::{ObfuscationPass, PassContext, PassRecord};
use crate::utils::crypto;

/// Dead code injection pass — inserts plausible but unreachable code.
pub struct DeadCodePass;

#[derive(Debug, Serialize, Deserialize)]
struct DeadCodeData {
    /// Names of injected dead functions.
    dead_functions: Vec<String>,
    /// Names of injected guard variables for unreachable branches.
    guard_variables: Vec<String>,
}

impl ObfuscationPass for DeadCodePass {
    fn name(&self) -> &'static str {
        "dead_code"
    }

    fn encrypt(
        &self,
        ast: &mut syn::File,
        context: &mut PassContext,
    ) -> Result<PassRecord> {
        let mut dead_functions = Vec::new();

        // 1. Generate dead functions
        let num_funcs = 2 + (crypto::hmac_sha256(&context.hmac_key, b"dead_func_count")[0] % 4)
            as usize;

        for i in 0..num_funcs {
            let hash = crypto::hmac_sha256(
                &context.hmac_key,
                format!("dead_func_{i}").as_bytes(),
            );
            let name = format!("_x{:02x}{:02x}{:02x}", hash[0], hash[1], hash[2]);
            let func = generate_dead_function(&name, &hash);
            ast.items.push(func);
            dead_functions.push(name);
        }

        // 2. Insert unreachable branches into existing functions
        let mut injector = BranchInjector {
            hmac_key: context.hmac_key.clone(),
            counter: 0,
            guard_variables: Vec::new(),
        };
        injector.visit_file_mut(ast);
        let guard_variables = injector.guard_variables;

        let data = DeadCodeData {
            dead_functions,
            guard_variables,
        };

        Ok(PassRecord {
            pass_name: self.name().to_string(),
            data: serde_json::to_value(data).expect("DeadCodeData serializes"),
        })
    }

    fn decrypt(
        &self,
        ast: &mut syn::File,
        record: &PassRecord,
        _context: &PassContext,
    ) -> Result<()> {
        let data: DeadCodeData =
            serde_json::from_value(record.data.clone()).map_err(|e| ApateError::PassFailed {
                pass: "dead_code".into(),
                reason: format!("failed to deserialize dead code data: {e}"),
            })?;

        // 1. Remove dead functions from top-level items
        ast.items.retain(|item| {
            if let syn::Item::Fn(func) = item {
                let name = func.sig.ident.to_string();
                !data.dead_functions.contains(&name)
            } else {
                true
            }
        });

        // 2. Remove unreachable branches from function bodies
        let mut remover = BranchRemover {
            guard_variables: data.guard_variables.into_iter().collect(),
        };
        remover.visit_file_mut(ast);

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Dead function generation
// ---------------------------------------------------------------------------

/// Generate a dead function with a plausible-looking body.
fn generate_dead_function(name: &str, hash: &[u8]) -> syn::Item {
    let func_ident = syn::Ident::new(name, proc_macro2::Span::call_site());
    let template = hash[3] % 4;

    match template {
        0 => {
            // fn name(a: usize, b: usize) -> usize
            syn::parse_quote! {
                #[allow(dead_code)]
                fn #func_ident(_a: usize, _b: usize) -> usize {
                    let _c = _a.wrapping_mul(_b);
                    let _d = _c.wrapping_add(1);
                    if _d > _a { _d } else { _a.wrapping_sub(_b) }
                }
            }
        }
        1 => {
            // fn name(s: &str) -> bool
            syn::parse_quote! {
                #[allow(dead_code)]
                fn #func_ident(_s: &str) -> bool {
                    let _len = _s.len();
                    let _half = _len / 2;
                    _half > 0 && _len < 1024
                }
            }
        }
        2 => {
            // fn name(n: u32) -> u32
            syn::parse_quote! {
                #[allow(dead_code)]
                fn #func_ident(_n: u32) -> u32 {
                    let mut _acc = 0u32;
                    let mut _i = 0u32;
                    while _i < _n % 16 {
                        _acc = _acc.wrapping_add(_i);
                        _i += 1;
                    }
                    _acc
                }
            }
        }
        3 => {
            // fn name(a: usize) -> Option<usize>
            syn::parse_quote! {
                #[allow(dead_code)]
                fn #func_ident(_a: usize) -> Option<usize> {
                    if _a == 0 {
                        None
                    } else {
                        let _r = _a.wrapping_mul(3).wrapping_add(7);
                        Some(_r % (_a + 1))
                    }
                }
            }
        }
        _ => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// Unreachable branch injection
// ---------------------------------------------------------------------------

struct BranchInjector {
    hmac_key: Vec<u8>,
    counter: usize,
    guard_variables: Vec<String>,
}

impl BranchInjector {
    fn should_inject(&self) -> bool {
        let hash = crypto::hmac_sha256(
            &self.hmac_key,
            format!("branch_{}", self.counter).as_bytes(),
        );
        hash[0] < 77 // ~30% chance
    }

    fn generate_guard_name(&self) -> String {
        let hash = crypto::hmac_sha256(
            &self.hmac_key,
            format!("guard_{}", self.counter).as_bytes(),
        );
        format!("_x{:02x}{:02x}g", hash[0], hash[1])
    }
}

impl VisitMut for BranchInjector {
    fn visit_item_fn_mut(&mut self, node: &mut syn::ItemFn) {
        // Don't recurse into nested functions — just handle this one
        if self.should_inject() {
            let guard_name = self.generate_guard_name();
            let guard_ident = syn::Ident::new(&guard_name, proc_macro2::Span::call_site());

            // Runtime let binding that evaluates to false (avoids const-fold warnings)
            let guard_stmt: syn::Stmt = syn::parse_quote! {
                let #guard_ident: bool = { let _a = 1u8; let _b = 2u8; _a > _b };
            };

            let branch_stmt: syn::Stmt = syn::parse_quote! {
                if #guard_ident {
                    let _x = 0usize;
                    let _y = _x.wrapping_add(1);
                    let _z = _y.wrapping_mul(2);
                }
            };

            // Insert at the beginning of the function body
            node.block.stmts.insert(0, branch_stmt);
            node.block.stmts.insert(0, guard_stmt);

            self.guard_variables.push(guard_name);
        }
        self.counter += 1;

        // Visit the body for nested items (but not for injection)
        syn::visit_mut::visit_item_fn_mut(self, node);
    }

    fn visit_impl_item_fn_mut(&mut self, node: &mut syn::ImplItemFn) {
        if self.should_inject() {
            let guard_name = self.generate_guard_name();
            let guard_ident = syn::Ident::new(&guard_name, proc_macro2::Span::call_site());

            let guard_stmt: syn::Stmt = syn::parse_quote! {
                let #guard_ident: bool = { let _a = 1u8; let _b = 2u8; _a > _b };
            };

            let branch_stmt: syn::Stmt = syn::parse_quote! {
                if #guard_ident {
                    let _x = 0usize;
                    let _y = _x.wrapping_add(1);
                    let _z = _y.wrapping_mul(2);
                }
            };

            node.block.stmts.insert(0, branch_stmt);
            node.block.stmts.insert(0, guard_stmt);

            self.guard_variables.push(guard_name);
        }
        self.counter += 1;

        syn::visit_mut::visit_impl_item_fn_mut(self, node);
    }
}

// ---------------------------------------------------------------------------
// Unreachable branch removal
// ---------------------------------------------------------------------------

struct BranchRemover {
    guard_variables: std::collections::HashSet<String>,
}

impl BranchRemover {
    /// Check if a statement is a guard let binding matching one of our names.
    fn is_guard_let(&self, stmt: &syn::Stmt) -> bool {
        if let syn::Stmt::Local(local) = stmt
            && let syn::Pat::Type(pat_type) = &local.pat
                && let syn::Pat::Ident(pat_ident) = &*pat_type.pat {
                    return self.guard_variables.contains(&pat_ident.ident.to_string());
                }
        false
    }

    /// Check if a statement is an if block using one of our guard variables.
    fn is_guard_if(&self, stmt: &syn::Stmt) -> bool {
        let expr = match stmt {
            syn::Stmt::Expr(expr, _) => expr,
            _ => return false,
        };
        let syn::Expr::If(expr_if) = expr else {
            return false;
        };
        // Check if the condition is a path matching a guard variable
        if let syn::Expr::Path(expr_path) = &*expr_if.cond
            && let Some(ident) = expr_path.path.get_ident() {
                return self.guard_variables.contains(&ident.to_string());
            }
        false
    }

    fn clean_block(&self, block: &mut syn::Block) {
        block
            .stmts
            .retain(|stmt| !self.is_guard_let(stmt) && !self.is_guard_if(stmt));
    }
}

impl VisitMut for BranchRemover {
    fn visit_item_fn_mut(&mut self, node: &mut syn::ItemFn) {
        self.clean_block(&mut node.block);
        syn::visit_mut::visit_item_fn_mut(self, node);
    }

    fn visit_impl_item_fn_mut(&mut self, node: &mut syn::ImplItemFn) {
        self.clean_block(&mut node.block);
        syn::visit_mut::visit_impl_item_fn_mut(self, node);
    }
}
