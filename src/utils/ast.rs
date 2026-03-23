/// Convert a `syn::File` AST back to formatted Rust source code.
pub fn file_to_source(file: &syn::File) -> String {
    prettyplease::unparse(file)
}
