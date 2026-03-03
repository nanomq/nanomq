#!/bin/bash

set -euo pipefail

DOWNLOAD_BASE_URL="${DOWNLOAD_BASE_URL:-https://www.emqx.com/en/downloads/emqx-edge}"
INSTALL_DIR="${INSTALL_DIR:-/opt/emqx-edge}"

TMP_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

die() {
  echo "$*" >&2
  exit 1
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    die "Missing required command: $1"
  fi
}

run_as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
    return
  fi

  if ! command -v sudo >/dev/null 2>&1; then
    die "This action requires root privileges, and sudo is not available."
  fi

  sudo "$@"
}

detect_arch() {
  local arch
  arch="$(uname -m)"
  case "${arch}" in
    x86_64|amd64)   echo "amd64" ;;
    aarch64|arm64)   echo "aarch64" ;;
    *)               die "Unsupported architecture: ${arch}" ;;
  esac
}

latest_version() {
  local version
  version="$(curl -fsSL "${DOWNLOAD_BASE_URL}" \
    | grep -Eo '/en/downloads/emqx-edge/v[0-9]+\.[0-9]+\.[0-9]+' \
    | sed 's#.*/##' \
    | awk '
      function gt(a, b,   av, bv, i) {
        split(a, av, ".")
        split(b, bv, ".")
        for (i = 1; i <= 3; i++) {
          if ((av[i] + 0) > (bv[i] + 0)) return 1
          if ((av[i] + 0) < (bv[i] + 0)) return 0
        }
        return 0
      }
      {
        gsub(/^v/, "", $0)
        if (best == "" || gt($0, best)) best = $0
      }
      END {
        if (best != "") print "v" best
      }
    ')"

  if [ -z "${version}" ]; then
    die "Failed to detect latest EMQX Edge version."
  fi
  echo "${version}"
}

verify_checksum() {
  local file="$1"
  local checksum_file="$2"
  local expected actual

  expected="$(grep -Eo '[A-Fa-f0-9]{64}' "${checksum_file}" | head -n 1 | tr '[:upper:]' '[:lower:]')"
  if [ -z "${expected}" ]; then
    die "Failed to parse SHA256 from ${checksum_file}"
  fi

  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "${file}" | awk '{print tolower($1)}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "${file}" | awk '{print tolower($1)}')"
  else
    die "Neither sha256sum nor shasum is available."
  fi

  if [ "${actual}" != "${expected}" ]; then
    echo "Checksum mismatch for ${file}" >&2
    echo "Expected: ${expected}" >&2
    echo "Actual:   ${actual}" >&2
    exit 1
  fi
}

install_emqx_edge() {
  if [ "$(uname -s)" = "Darwin" ]; then
    die "macOS is not supported. Please install via Docker: https://docs.emqx.com/en/emqx-edge/latest/installation/docker.html"
  fi

  require_cmd curl
  require_cmd grep
  require_cmd awk
  require_cmd unzip

  local version arch version_num package package_url sha_url archive_file checksum_file
  version="${EMQX_VERSION:-$(latest_version)}"
  arch="$(detect_arch)"
  version_num="${version#v}"
  package="emqx-edge-${version_num}-linux-${arch}.zip"

  package_url="${DOWNLOAD_BASE_URL}/${version}/${package}"
  sha_url="${package_url}.sha256"
  archive_file="${TMP_DIR}/${package}"
  checksum_file="${archive_file}.sha256"

  echo "Version: ${version}"
  echo "Architecture: ${arch}"
  echo "Package: ${package}"

  echo "Downloading package..."
  curl -fL --retry 3 -o "${archive_file}" "${package_url}"

  echo "Downloading checksum..."
  curl -fL --retry 3 -o "${checksum_file}" "${sha_url}"

  echo "Verifying checksum..."
  verify_checksum "${archive_file}" "${checksum_file}"

  echo "Extracting..."
  unzip -q "${archive_file}" -d "${TMP_DIR}"

  echo "Installing to ${INSTALL_DIR}..."
  run_as_root rm -rf "${INSTALL_DIR}"
  run_as_root mv "${TMP_DIR}/emqx-edge-${version_num}-linux-${arch}" "${INSTALL_DIR}"

  # Add to PATH via /etc/profile.d
  local profile_script="/etc/profile.d/emqx-edge.sh"
  printf 'export PATH="%s:${PATH}"\n' "${INSTALL_DIR}" \
    | run_as_root tee "${profile_script}" >/dev/null
  run_as_root chmod 644 "${profile_script}"

  echo
  echo "EMQX Edge ${version} installed to ${INSTALL_DIR}"
  echo "Run 'source ${profile_script}' or start a new shell to update PATH."
}

install_emqx_edge "$@"
