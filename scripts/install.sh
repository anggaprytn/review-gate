#!/bin/sh
set -eu
if (set -o pipefail) 2>/dev/null; then
  set -o pipefail
fi

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BIN_NAME="reviewgate"
DEFAULT_REPO="anggaprytn/review-gate"
DRY_RUN="${REVIEWGATE_INSTALL_DRY_RUN:-false}"

error() {
  printf '%s\n' "error: $*" >&2
  exit 1
}

no_prebuilt() {
  printf '%s\n' "error: No prebuilt ReviewGate binary is available for $1/$2." >&2
  printf '%s\n' "Build from source with: cargo install --path ." >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || error "$1 is required"
}

normalize_repo() {
  value="$1"
  value="${value#git@github.com:}"
  value="${value#https://github.com/}"
  value="${value#http://github.com/}"
  value="${value%.git}"
  printf '%s\n' "$value"
}

resolve_repo() {
  normalize_repo "${REVIEWGATE_REPO:-$DEFAULT_REPO}"
}

detect_target() {
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os:$arch" in
    Linux:x86_64|Linux:amd64)
      printf '%s\n' "x86_64-unknown-linux-gnu"
      ;;
    Darwin:arm64|Darwin:aarch64)
      printf '%s\n' "aarch64-apple-darwin"
      ;;
    Darwin:x86_64|Darwin:amd64)
      printf '%s\n' "x86_64-apple-darwin"
      ;;
    Linux:arm64|Linux:aarch64)
      printf '%s\n' "aarch64-unknown-linux-gnu"
      ;;
    *)
      no_prebuilt "$os" "$arch"
      ;;
  esac
}

resolve_version() {
  if [ -n "${REVIEWGATE_VERSION:-}" ]; then
    printf '%s\n' "$REVIEWGATE_VERSION"
    return
  fi

  latest_url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/${repo}/releases/latest")"
  case "$latest_url" in
    */releases/tag/*) ;;
    *) error "could not resolve latest release for ${repo}" ;;
  esac
  version="${latest_url##*/}"
  [ -n "$version" ] && [ "$version" != "latest" ] || error "could not resolve latest release for ${repo}"
  printf '%s\n' "$version"
}

verify_checksum() {
  archive="$1"

  grep "  ${archive}\$" checksums.txt > "${archive}.sha256" || error "checksums.txt does not include ${archive}"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c "${archive}.sha256"
    return
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "${archive}.sha256"
    return
  fi

  error "shasum or sha256sum is required"
}

install_binary() {
  src="$1"
  dest="$2"

  mkdir -p "$INSTALL_DIR" 2>/dev/null || true

  if [ -w "$INSTALL_DIR" ]; then
    install -m 0755 "$src" "$dest"
    return
  fi

  if command -v sudo >/dev/null 2>&1; then
    printf '%s\n' "install directory is not writable; using sudo for $INSTALL_DIR"
    sudo mkdir -p "$INSTALL_DIR"
    sudo install -m 0755 "$src" "$dest"
    return
  fi

  error "install directory is not writable: $INSTALL_DIR"
}

repo="$(resolve_repo)"
os="$(uname -s)"
arch="$(uname -m)"
target="$(detect_target)"

if [ "$DRY_RUN" = "true" ] && [ -z "${REVIEWGATE_VERSION:-}" ]; then
  version="latest"
else
  if [ -z "${REVIEWGATE_VERSION:-}" ]; then
    need curl
  fi
  version="$(resolve_version)"
fi

if [ "$version" = "latest" ]; then
  archive="reviewgate-<version>-${target}.tar.gz"
  asset_url="https://github.com/${repo}/releases/latest/download/${archive}"
else
  archive="reviewgate-${version}-${target}.tar.gz"
  asset_url="https://github.com/${repo}/releases/download/${version}/${archive}"
fi
checksum_url="https://github.com/${repo}/releases/download/${version}/checksums.txt"

if [ "$DRY_RUN" = "true" ]; then
  printf '%s\n' "ReviewGate install dry run"
  printf '%s\n' "detected OS: ${os}"
  printf '%s\n' "detected arch: ${arch}"
  printf '%s\n' "target triple: ${target}"
  printf '%s\n' "repo: ${repo}"
  printf '%s\n' "release version/latest: ${version}"
  printf '%s\n' "asset URL: ${asset_url}"
  printf '%s\n' "install dir: ${INSTALL_DIR}"
  exit 0
fi

need curl
need tar

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT INT TERM

printf '%s\n' "Downloading ReviewGate ${version} from ${repo} (${target})"
curl -fsIL "$asset_url" >/dev/null 2>&1 || no_prebuilt "$os" "$arch"
curl -fsSL "$asset_url" -o "${tmp_dir}/${archive}"
curl -fsSL "$checksum_url" -o "${tmp_dir}/checksums.txt"

(
  cd "$tmp_dir"
  verify_checksum "$archive"
  tar -xzf "$archive"
)

[ -f "${tmp_dir}/${BIN_NAME}" ] || error "archive did not contain ${BIN_NAME}"

install_binary "${tmp_dir}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
printf '%s\n' "Installed ${BIN_NAME} to ${INSTALL_DIR}/${BIN_NAME}"
