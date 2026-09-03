# Contributing

## Development

1. Install Rust stable.
2. Run `cargo test --workspace` from repository root.
3. Keep security-sensitive logic in Rust crates.

## Pull requests

- Add focused tests for behavior changes.
- Avoid introducing secret logging or plaintext key material in output.
