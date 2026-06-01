#!/bin/sh
set -eu
if (set -o pipefail) 2>/dev/null; then
  set -o pipefail
fi

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BIN_NAME="reviewgate"

error() {
  printf '%s\n' "error: $*" >&2
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

infer_repo() {
  if [ -n "${REVIEWGATE_REPO:-}" ]; then
    normalize_repo "$REVIEWGATE_REPO"
    return
  fi

  if command -v git >/dev/null 2>&1; then
    remote="$(git config --get remote.origin.url 2>/dev/null || true)"
    if [ -n "$remote" ]; then
      normalize_repo "$remote"
      return
    fi
  fi

  printf '%s\n' "Anggaprytn/review-gate"
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
    *)
      error "unsupported platform: $os $arch"
      ;;
  esac
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

need curl
need tar
need shasum

repo="$(infer_repo)"
target="$(detect_target)"
archive="reviewgate-${target}.tar.gz"
base_url="https://github.com/${repo}/releases/latest/download"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT INT TERM

printf '%s\n' "Downloading ReviewGate from ${repo} (${target})"
curl -fsSL "${base_url}/${archive}" -o "${tmp_dir}/${archive}"
curl -fsSL "${base_url}/${archive}.sha256" -o "${tmp_dir}/${archive}.sha256"

(
  cd "$tmp_dir"
  shasum -a 256 -c "${archive}.sha256"
  tar -xzf "$archive"
)

[ -f "${tmp_dir}/${BIN_NAME}" ] || error "archive did not contain ${BIN_NAME}"

install_binary "${tmp_dir}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
printf '%s\n' "Installed ${BIN_NAME} to ${INSTALL_DIR}/${BIN_NAME}"
