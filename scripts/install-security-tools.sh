#!/usr/bin/env bash
set -euo pipefail

# These archive digests are the published GitHub release-asset SHA-256 values.
# Update the version and all supported-platform digests together after review.
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)
    zizmor_asset=zizmor-x86_64-unknown-linux-gnu.tar.gz
    zizmor_sha=d185f726bdaf92df78273217dfdd24ebcd6b0ef48cf3ce776ff5762b6e138c99
    gitleaks_asset=gitleaks_8.30.1_linux_x64.tar.gz
    gitleaks_sha=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
    osv_asset=osv-scanner_linux_amd64
    osv_sha=160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b
    ;;
  Darwin/arm64)
    zizmor_asset=zizmor-aarch64-apple-darwin.tar.gz
    zizmor_sha=ad5aa633cd56215b11e6c51d51f90c7e6b22904a75047d1215abbd422f61d698
    gitleaks_asset=gitleaks_8.30.1_darwin_arm64.tar.gz
    gitleaks_sha=b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5
    osv_asset=osv-scanner_darwin_arm64
    osv_sha=d4926ef8da134332543be276dff157e4c170f99ad91fc48e89448a8816bdf70b
    ;;
  *) echo 'Security tools support Linux x86_64 and macOS arm64' >&2; exit 2 ;;
esac

install_root="${1:-local/generated/security-tools}"
mkdir -p "$install_root"
install_root="$(cd "$install_root" && pwd)"
download_dir="$(mktemp -d "${TMPDIR:-/tmp}/mikaki-security-tools.XXXXXX")"
trap 'rm -rf "$download_dir"' EXIT

download() {
  local repository="$1" version="$2" asset="$3" expected="$4" binary="$5"
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 120 --retry 2 \
    "https://github.com/$repository/releases/download/$version/$asset" \
    --output "$download_dir/$asset"
  local actual
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$download_dir/$asset")"
  else
    actual="$(shasum -a 256 "$download_dir/$asset")"
  fi
  if [ "${actual%% *}" != "$expected" ]; then
    echo "Security tool archive checksum mismatch: $binary" >&2
    exit 1
  fi
  if [[ "$asset" == *.tar.gz ]]; then
    tar -xzf "$download_dir/$asset" -C "$download_dir" "$binary"
    install -m 0755 "$download_dir/$binary" "$install_root/$binary"
  else
    install -m 0755 "$download_dir/$asset" "$install_root/$binary"
  fi
}

download zizmorcore/zizmor v1.31.1 "$zizmor_asset" "$zizmor_sha" zizmor
download gitleaks/gitleaks v8.30.1 "$gitleaks_asset" "$gitleaks_sha" gitleaks
download google/osv-scanner v2.7.0 "$osv_asset" "$osv_sha" osv-scanner
"$install_root/zizmor" --version
"$install_root/gitleaks" version
"$install_root/osv-scanner" --version
if [ -n "${GITHUB_PATH:-}" ]; then
  printf '%s\n' "$install_root" >> "$GITHUB_PATH"
fi
