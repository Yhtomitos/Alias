#!/usr/bin/env bash
set -euo pipefail

echo "== Rust format =="
cargo fmt --all --check -- --config-path static-analysis/formatters/rustfmt.toml

echo "== Rust lint =="
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "== Rust dependency policy =="
cargo deny --config static-analysis/dependency-policy/deny.toml check

echo "== JS/TS toolchain install =="
npm ci

echo "== JS/TS format =="
npm run format:check

echo "== JS/TS lint =="
npm run lint

echo "== TypeScript strict type check =="
npm run typecheck

echo "== Dependency vulnerabilities =="
osv_args=(scan source --lockfile=Cargo.lock)

if [[ -f package-lock.json ]]; then
  osv_args+=(--lockfile=package-lock.json)
fi

osv-scanner "${osv_args[@]}"

echo "== Secret detection =="
gitleaks detect --source . --config static-analysis/secret-detection/gitleaks.toml --redact --no-banner

echo "== Tauri hardening =="
bash static-analysis/tauri/hardening-check.sh

