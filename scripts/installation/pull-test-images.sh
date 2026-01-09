#!/bin/bash

# Pre-pull container images required for Tracee tests.
# Uses ECR Public mirrors to avoid Docker Hub rate limits.
# Images are cached on the runner for subsequent test steps.
#
# Usage: pull-test-images.sh [--force/-f]
#   --force, -f    Remove existing images before pulling (default: false)

set -euo pipefail

# Source lib.sh for consistent logging and utilities
__LIB_DIR="${0%/*}/.."
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

# Verify docker is available
require_cmds docker

# List of container images required for tests
# Using ECR Public mirrors where possible to avoid Docker Hub rate limits
IMAGES="
public.ecr.aws/docker/library/busybox:1.37.0@sha256:e3652a00a2fabd16ce889f0aa32c38eec347b997e73bd09e69c962ec7f8732ee
public.ecr.aws/docker/library/ubuntu:jammy-20240911.1@sha256:0e5e4a57c2499249aafc3b40fcd541e9a456aab7296681a3994d631587203f97
ghcr.io/aquasecurity/tracee-tester:latest@sha256:7f93e117d9b5ba99797171805139238f6c91a80dbd77846eb7e35587e4c70a6e
"

# Delay between pulls to diminish load on registries
PULL_DELAY_SECONDS=1

# Check if an image exists locally
image_exists() {
    local image="$1"
    docker image inspect "${image}" > /dev/null 2>&1
}

# Remove an image if it exists
remove_image() {
    local image="$1"
    if image_exists "${image}"; then
        info "Removing existing image: ${image}"
        docker image rm -f "${image}" > /dev/null 2>&1 || die "Failed to remove image: ${image}"
    fi
}

# Pull all test images
pull_images() {
    local force="$1"

    info "Pre-pulling container images for tests..."
    info "Using ECR Public mirrors to avoid Docker Hub rate limits"

    for image in ${IMAGES}; do
        if [[ "${force}" == "true" ]]; then
            remove_image "${image}"
        fi

        if image_exists "${image}"; then
            if [[ "${force}" == "true" ]]; then
                error "Image should not exist after removal: ${image}"
                die "Failed to remove image: ${image}"
            fi

            info "Image already exists, skipping: ${image}"
            continue
        fi

        info "Pulling ${image}..."
        docker image pull "${image}" || die "Failed to pull image: ${image}"
        sleep "${PULL_DELAY_SECONDS}"
    done

    info "All test images pre-pulled and cached"
}

# Main
main() {
    local force="false"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --force | -f)
                force="true"
                shift
                ;;
            --help | -h)
                echo "Usage: ${0##*/} [--force]"
                echo "  --force, -f    Remove existing images before pulling"
                exit 0
                ;;
            *)
                warn "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    pull_images "${force}"
}

main "$@"
