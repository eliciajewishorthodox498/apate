/// Process an input string by trimming and wrapping.
pub fn process(input: &str) -> String {
    let trimmed = input.trim();
    format!("Processed: {}", trimmed)
}

/// Double a number and add one.
pub fn helper(n: u32) -> u32 {
    n * 2 + 1
}

fn internal_detail(x: u32) -> u32 {
    x.wrapping_add(42)
}
