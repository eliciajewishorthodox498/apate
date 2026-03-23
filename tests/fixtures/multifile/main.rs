mod utils;

fn main() {
    let result = utils::process("test input");
    println!("Result: {}", result);

    let doubled = utils::helper(21);
    println!("Doubled: {}", doubled);
}
