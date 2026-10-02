#!/usr/bin/env bash
set -euo pipefail

# Cache only these tools and Cargo installation metadata, never Cargo credentials
# or product build outputs. Changes here invalidate every profile's cache key.
case "${1:-}" in
  verify) tools=(wasm-pack@0.15.0 worker-build@0.8.6 cargo-llvm-cov@0.9.1) ;;
  audit) tools=(cargo-audit@0.22.2) ;;
  worker) tools=(worker-build@0.8.6) ;;
  release) tools=(cargo-cyclonedx@0.5.9 worker-build@0.8.6) ;;
  *) echo 'Unknown CI tool profile' >&2; exit 2 ;;
esac

install_root="${RUNNER_TEMP:?}/mikaki-ci-tools-$1"
for tool in "${tools[@]}"; do
  # Always run the pinned install: Cargo checks its restored installation metadata
  # and skips compilation only when the requested version is already installed.
  cargo install "${tool%@*}" --version "${tool#*@}" --locked --root "$install_root"
done
printf '%s\n' "$install_root/bin" >> "${GITHUB_PATH:?}"
