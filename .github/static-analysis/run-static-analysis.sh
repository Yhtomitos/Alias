#!/usr/bin/env bash
set -euo pipefail

echo "== Rust format =="
cargo fmt --all --check

echo "== Rust lint =="
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "== Rust dependency policy =="
cargo deny check

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
gitleaks detect --source . --config .gitleaks.toml --redact --no-banner

echo "== Tauri hardening =="
tauri_configs=$(find . -path '*/src-tauri/tauri.conf.json' -o -path '*/src-tauri/tauri.conf.json5' -o -path '*/src-tauri/capabilities/*.json')
if [[ -z "${tauri_configs}" ]]; then
  echo "No Tauri app configuration found yet; hardening check is pending until a Tauri app is added."
else
  missing=0
  while IFS= read -r tauri_conf; do
    [[ -z "${tauri_conf}" ]] && continue
    if [[ "${tauri_conf}" == *.json5 ]]; then
      if ! grep -Eq '(^|[^[:alnum:]_])csp[[:space:]]*:' "${tauri_conf}"; then
        echo "Missing CSP in ${tauri_conf}"
        missing=1
      fi
    elif ! jq -e '.app.security.csp // .tauri.security.csp' "${tauri_conf}" >/dev/null; then
      echo "Missing CSP in ${tauri_conf}"
      missing=1
    fi
  done < <(find . -path '*/src-tauri/tauri.conf.json' -o -path '*/src-tauri/tauri.conf.json5')

  if find . -path '*/src-tauri/tauri.conf.json' -o -path '*/src-tauri/tauri.conf.json5' | grep -q .; then
    if ! find . -path '*/src-tauri/capabilities/*.json' | grep -q .; then
      echo "Missing Tauri capability files under src-tauri/capabilities."
      missing=1
    fi
  fi

  if [[ "${missing}" -ne 0 ]]; then
    exit 1
  fi
fi
