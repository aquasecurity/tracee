#!/bin/sh

# Install the Firecracker microVM binary (and jailer) from a pinned release,
# checksum-verified against a vendored sha256. Used by the ubuntu-fc build
# environment stage to run the kernel-tampering E2E tests in a throwaway VM
# (see scripts/e2e-firecracker.sh).

set -e

# Source lib.sh for consistent logging and utilities
SCRIPT_DIR="${0%/*}"
__LIB_DIR="${SCRIPT_DIR}/.."
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

FIRECRACKER_VERSION="${FIRECRACKER_VERSION:-v1.13.1}"

require_cmds curl tar

arch=$(uname -m)
case "${arch}" in
    x86_64 | aarch64) ;;
    *) die "Unsupported architecture for Firecracker: ${arch}" ;;
esac

tarball="firecracker-${FIRECRACKER_VERSION}-${arch}.tgz"
checksum_file="${SCRIPT_DIR}/checksums/${tarball}.sha256"
url="https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/${tarball}"

[ -f "${checksum_file}" ] || die "Firecracker checksum file not found: ${checksum_file}"

info "Downloading Firecracker ${FIRECRACKER_VERSION} (${arch})"
tmp=$(mktemp -d)
trap 'rm -rf "${tmp}"' EXIT

curl -fsSL -o "${tmp}/${tarball}" "${url}" || die "failed to download ${url}"

if ! verify_sha256_checksum "${tmp}/${tarball}" "${checksum_file}" "Firecracker ${FIRECRACKER_VERSION}"; then
    die "Firecracker checksum verification failed"
fi

# --no-same-owner: the release tarball records AWS build-host uids/gids that
# are unmappable inside a rootless (userns) container build, which otherwise
# fails the extraction; ownership is irrelevant, we only take two binaries
tar --no-same-owner -C "${tmp}" -xzf "${tmp}/${tarball}"

# release layout: release-<ver>-<arch>/{firecracker,jailer}-<ver>-<arch>
rel="${tmp}/release-${FIRECRACKER_VERSION}-${arch}"
install -m 0755 "${rel}/firecracker-${FIRECRACKER_VERSION}-${arch}" /usr/local/bin/firecracker
install -m 0755 "${rel}/jailer-${FIRECRACKER_VERSION}-${arch}" /usr/local/bin/jailer

firecracker --version | head -n1

info "Firecracker installed successfully"
