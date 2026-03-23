# Contributing to Apate

You want to contribute to a source code obfuscation tool. Respect.

## Getting Started

```bash
git clone https://github.com/dmriding/apate.git
cd apate
cargo build
cargo test
```

If the tests pass, you're good. If they don't, that's on you.

## Pull Requests

Open a PR. Make sure it compiles, passes `cargo test`, and doesn't make `cargo clippy` angry. That's it.

If your PR adds a new obfuscation pass, include tests proving:
- Roundtrip: encrypt → decrypt == original (byte-for-byte)
- Determinism: same key + same input == same output
- The obfuscated output actually compiles

## Issues

Found a bug? Open an issue. Include:
- What you ran
- What happened
- What you expected to happen
- The Rust version (`rustc --version`)

"It doesn't work" is not a bug report.

## Code Style

- `cargo fmt`
- `cargo clippy` with zero warnings
- If you're adding to the rename pass, god help you

## License

By contributing, you agree that your contribution is licensed under the [WTFPL](LICENSE).

You can do whatever the fuck you want with it.
