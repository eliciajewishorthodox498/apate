/// A simple greeting function
/// that says hello to someone.
fn greet(name: &str) -> String {
    // Build the greeting
    let greeting = format!("Hello, {}!", name);

    // Log it for debugging
    println!("Generated greeting: {}", greeting);

    greeting
}

fn add(a: i32, b: i32) -> i32 {
    a + b
}

fn is_even(n: u64) -> bool {
    if n % 2 == 0 {
        true
    } else {
        false
    }
}

fn main() {
    let message = greet("World");
    let sum = add(20, 22);
    let even = is_even(42);
    println!("{} — sum: {}, even: {}", message, sum, even);
}
