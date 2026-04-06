use serde::{Deserialize, Serialize};
use syn::visit_mut::VisitMut;

use crate::error::{ApateError, Result};
use crate::passes::{ObfuscationPass, PassContext, PassRecord};
use crate::utils::crypto;

/// String encoding pass — XOR-encodes string literals so they don't appear in plaintext.
pub struct StringPass;

#[derive(Debug, Serialize, Deserialize)]
struct StringData {
    /// Original string literals in encounter order.
    originals: Vec<StringRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StringRecord {
    index: usize,
    original: String,
}

impl ObfuscationPass for StringPass {
    fn name(&self) -> &'static str {
        "strings"
    }

    fn encrypt(
        &self,
        ast: &mut syn::File,
        context: &mut PassContext,
    ) -> Result<PassRecord> {
        let mut encoder = StringEncoder {
            xor_key: context.xor_key.clone(),
            file_path: context.current_file.to_string_lossy().into_owned(),
            hmac_key: context.hmac_key.clone(),
            counter: 0,
            originals: Vec::new(),
            in_const_static: false,
            in_attribute: false,
        };
        encoder.visit_file_mut(ast);

        let data = StringData {
            originals: encoder.originals,
        };

        Ok(PassRecord {
            pass_name: self.name().to_string(),
            data: serde_json::to_value(data).expect("StringData serializes"),
        })
    }

    fn decrypt(
        &self,
        ast: &mut syn::File,
        record: &PassRecord,
        _context: &PassContext,
    ) -> Result<()> {
        let data: StringData =
            serde_json::from_value(record.data.clone()).map_err(|e| ApateError::PassFailed {
                pass: "strings".into(),
                reason: format!("failed to deserialize string data: {e}"),
            })?;

        let mut decoder = StringDecoder {
            originals: data.originals,
            counter: 0,
        };
        decoder.visit_file_mut(ast);

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Encrypt: replace string literals with XOR decode blocks
// ---------------------------------------------------------------------------

struct StringEncoder {
    xor_key: Vec<u8>,
    file_path: String,
    hmac_key: Vec<u8>,
    counter: usize,
    originals: Vec<StringRecord>,
    in_const_static: bool,
    in_attribute: bool,
}

impl StringEncoder {
    /// Derive a per-string XOR key byte.
    fn derive_xor_byte(&self, index: usize) -> u8 {
        let mut input = self.xor_key.clone();
        input.extend_from_slice(self.file_path.as_bytes());
        input.extend_from_slice(&index.to_le_bytes());
        let hash = crypto::blake3_hash(&input);
        // Avoid zero key (XOR with 0 is identity)
        if hash[0] == 0 { hash[1] | 1 } else { hash[0] }
    }

    /// Generate a keyed static name for the decode block.
    fn static_name(&self, index: usize) -> String {
        let hash = crypto::hmac_sha256(&self.hmac_key, &index.to_le_bytes());
        format!("_x{:02x}{:02x}", hash[0], hash[1])
    }

    /// Build the XOR decode block expression for a string.
    ///
    /// Uses `LazyLock` to decode once and cache the result, avoiding the
    /// memory leak of `Box::leak` and the unsoundness of `from_utf8_unchecked`.
    fn build_decode_block(&self, value: &str, index: usize) -> syn::Expr {
        let xor_byte = self.derive_xor_byte(index);
        let xored: Vec<u8> = value.as_bytes().iter().map(|b| b ^ xor_byte).collect();
        let len = xored.len();

        let static_name = self.static_name(index);
        let static_ident = syn::Ident::new(&static_name, proc_macro2::Span::call_site());

        let xored_tokens: Vec<proc_macro2::TokenStream> = xored
            .iter()
            .map(|b| {
                let lit = syn::LitByte::new(*b, proc_macro2::Span::call_site());
                quote::quote! { #lit }
            })
            .collect();

        let xor_lit = syn::LitByte::new(xor_byte, proc_macro2::Span::call_site());
        let len_lit = syn::LitInt::new(&len.to_string(), proc_macro2::Span::call_site());

        syn::parse_quote! {
            {
                static #static_ident: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
                    const __D: [u8; #len_lit] = [#(#xored_tokens),*];
                    const __K: u8 = #xor_lit;
                    let mut __b = __D;
                    let mut __i = 0usize;
                    while __i < __b.len() {
                        __b[__i] ^= __K;
                        __i += 1;
                    }
                    String::from_utf8(__b.to_vec()).expect("apate: invalid utf8")
                });
                #static_ident.as_str()
            }
        }
    }
}

impl VisitMut for StringEncoder {
    fn visit_attribute_mut(&mut self, node: &mut syn::Attribute) {
        self.in_attribute = true;
        syn::visit_mut::visit_attribute_mut(self, node);
        self.in_attribute = false;
    }

    fn visit_item_const_mut(&mut self, node: &mut syn::ItemConst) {
        self.in_const_static = true;
        syn::visit_mut::visit_item_const_mut(self, node);
        self.in_const_static = false;
    }

    fn visit_item_static_mut(&mut self, node: &mut syn::ItemStatic) {
        self.in_const_static = true;
        syn::visit_mut::visit_item_static_mut(self, node);
        self.in_const_static = false;
    }

    fn visit_expr_mut(&mut self, node: &mut syn::Expr) {
        // First recurse into sub-expressions
        syn::visit_mut::visit_expr_mut(self, node);

        // Then check if this expression is a string literal we should encode
        if self.in_const_static || self.in_attribute {
            return;
        }

        if let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(lit_str), .. }) = node {
            let value = lit_str.value();
            if value.is_empty() {
                return;
            }

            let index = self.counter;
            self.originals.push(StringRecord {
                index,
                original: value.clone(),
            });

            *node = self.build_decode_block(&value, index);
            self.counter += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Decrypt: replace XOR decode blocks with original string literals
// ---------------------------------------------------------------------------

struct StringDecoder {
    originals: Vec<StringRecord>,
    counter: usize,
}

impl StringDecoder {
    /// Check if an expression is a XOR decode block.
    ///
    /// Recognizes both the new `LazyLock` pattern and the legacy `Box::leak` +
    /// `from_utf8_unchecked` pattern for backwards compatibility.
    fn is_decode_block(expr: &syn::Expr) -> bool {
        if let syn::Expr::Block(block) = expr {
            let tokens = quote::quote! { #block }.to_string();
            // New pattern: LazyLock-based decode block
            if tokens.contains("LazyLock") && tokens.contains("from_utf8") {
                return true;
            }
            // Legacy pattern: unsafe Box::leak + from_utf8_unchecked
            if tokens.contains("from_utf8_unchecked") {
                return true;
            }
        }
        false
    }
}

impl VisitMut for StringDecoder {
    fn visit_expr_mut(&mut self, node: &mut syn::Expr) {
        // First recurse
        syn::visit_mut::visit_expr_mut(self, node);

        // Then check if this is a decode block to replace
        if Self::is_decode_block(node)
            && let Some(record) = self.originals.get(self.counter)
        {
            let original_str = syn::LitStr::new(
                &record.original,
                proc_macro2::Span::call_site(),
            );
            *node = syn::Expr::Lit(syn::ExprLit {
                attrs: Vec::new(),
                lit: syn::Lit::Str(original_str),
            });
            self.counter += 1;
        }
    }
}
