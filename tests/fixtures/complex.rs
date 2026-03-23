use std::fmt;

const VERSION: &str = "1.0.0";
static MAX_ITEMS: u32 = 100;

fn process<T: fmt::Display>(items: &[T]) -> String {
    let mut result = String::new();
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            result.push_str(", ");
        }
        result.push_str(&format!("{}", item));
    }
    result
}

fn categorize(n: i32) -> &'static str {
    if n < 0 {
        "negative"
    } else if n == 0 {
        "zero"
    } else if n < 10 {
        "small"
    } else if n < 100 {
        "medium"
    } else {
        "large"
    }
}

fn sum_range(start: u32, end: u32) -> u32 {
    let mut total = 0;
    let mut i = start;
    while i < end {
        total += i;
        i += 1;
    }
    total
}

fn apply_twice(f: impl Fn(i32) -> i32, x: i32) -> i32 {
    f(f(x))
}

#[derive(Debug)]
struct Config {
    name: String,
    value: u32,
    enabled: bool,
}

impl Config {
    fn new(name: &str, value: u32) -> Self {
        Config {
            name: name.to_string(),
            value,
            enabled: true,
        }
    }

    fn describe(&self) -> String {
        if self.enabled {
            format!("{}: {} (active)", self.name, self.value)
        } else {
            format!("{}: disabled", self.name)
        }
    }
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.describe())
    }
}

fn main() {
    let numbers = vec![42, 17, 99];
    let result = process(&numbers);
    println!("Version {} — items: {}", VERSION, result);

    let category = categorize(42);
    println!("42 is {}", category);

    let total = sum_range(1, 11);
    println!("Sum 1..10 = {}", total);

    let doubled = apply_twice(|x| x * 2, 3);
    println!("3 doubled twice = {}", doubled);

    let cfg = Config::new("threshold", 50);
    println!("Config: {}", cfg);

    let max = MAX_ITEMS;
    println!("Max items: {}", max);
}
