# Contributing

## Development

1. Install Rust stable.
2. Run `cargo test --workspace` from repository root.
3. Keep security-sensitive logic in Rust crates.

## Pull requests

- Add focused tests for behavior changes.
- Avoid introducing secret logging or plaintext key material in output.
- Update API and project documentation in the same change. Follow `docs/api-documentation.md` for Rust, TypeScript, Python, HTML, CSS, and Markdown conventions.
