#!/bin/bash -e

# This script downloads & updates 2 repos inside tracee dir structure:
#
#     1) ./3rdparty/btfhub
#     2) ./3rdparty/btfhub/archive
#
# It uses the 2 repositories to generate tailored BTF files, according to
# latest CO-RE object file, so those files can be embedded in tracee Go binary.
#
# Note: You may opt out from fetching repositories changes in the beginning of
# the execution by exporting SKIP_FETCH=1 env variable.

__LIB_DIR="${0%/*}"
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

require_cmds git grep # optional: nproc

BASEDIR=$(cd "${0%/*}/../" && pwd)
cd "${BASEDIR}"

TRACEE_BPF_CORE="${BASEDIR}/dist/tracee.bpf.o"
BTFHUB_REPO="https://github.com/aquasecurity/btfhub.git"
BTFHUB_DIR="${BASEDIR}/3rdparty/btfhub"
BTFHUB_ARCHIVE_REPO="https://github.com/aquasecurity/btfhub-archive.git"
ARCHIVE_DIR="${BASEDIR}/3rdparty/btfhub/archive"
ARCH=$(uname -m)

case ${ARCH} in
    "x86_64")
        ARCH="x86_64"
        ;;
    "aarch64")
        ARCH="arm64"
        ;;
    *)
        die "unsupported architecture"
        ;;
esac

branch_clean() {
    cd "$1" || die "could not change dirs"

    # small sanity check
    [ ! -d ./.git ] && die "$(basename "$(pwd)") not a repo dir"

    info "Cleaning up $1..."
    git fetch -a || die "could not fetch $1" # make sure its updated
    git clean -fdX                           # clean leftovers
    git reset --hard                         # reset leftovers
    git checkout origin/main -b main-$$
    git branch -D main
    git branch -m main-$$ main # origin/main == main

    cd "${BASEDIR}"
}

[ ! -f "${TRACEE_BPF_CORE}" ] && die "tracee CO-RE obj not found"

if [ ! -d "${BTFHUB_DIR}" ]; then
    info "Cloning btfhub..."
    git clone "${BTFHUB_REPO}" "${BTFHUB_DIR}"
fi

if [ -z "${SKIP_FETCH}" ]; then
    branch_clean "${BTFHUB_DIR}"
fi

cd "${BTFHUB_DIR}"

info "Using sparse checkout for efficient BTF downloads (${ARCH} architecture)..."

# Handle existing archive directory intelligently
if [ -d "${ARCHIVE_DIR}" ] && [ -d "${ARCHIVE_DIR}/.git" ]; then
    if [ -n "${SKIP_FETCH}" ]; then
        info "Reusing existing archive (SKIP_FETCH set)..."
    else
        info "Updating existing archive with sparse checkout..."
        cd "${ARCHIVE_DIR}"
        git fetch origin main || die "failed to fetch archive updates"
        git reset --hard origin/main || die "failed to reset archive"
        cd -
    fi
else
    info "Creating new archive with sparse checkout..."
    rm -rf "${ARCHIVE_DIR}"

    info "Cloning btfhub-archive with optimized sparse checkout..."
    # Clone with minimal download - no blobs, no checkout initially
    git clone \
        --filter=blob:none \
        --no-checkout \
        --single-branch \
        --depth=1 \
        "${BTFHUB_ARCHIVE_REPO}" \
        "${ARCHIVE_DIR}" || die "failed to clone btfhub-archive"
fi

cd "${ARCHIVE_DIR}"

# Ensure sparse checkout is configured (whether new or existing)
git config core.sparseCheckout true
git sparse-checkout init --no-cone

info "Setting targeted sparse checkout patterns..."
SPARSE_CHECKOUT_FILE=".git/info/sparse-checkout"

# Include all, exclude 3.x/4.x kernels, re-include RHEL/CentOS 8
cat > "${SPARSE_CHECKOUT_FILE}" << EOF
# Include all BTF files for current architecture
*/*/${ARCH}/*.btf.tar.xz

# Exclude kernel 3.x versions
!*/*/${ARCH}/3.*.btf.tar.xz

# Exclude kernel 4.x versions
!*/*/${ARCH}/4.*.btf.tar.xz

# Re-include RHEL 8 (4.18 kernels with eBPF backports)
rhel/8/${ARCH}/*.btf.tar.xz

# Re-include CentOS 8 (4.18 kernels with eBPF backports)
centos/8/${ARCH}/*.btf.tar.xz
EOF

info "Downloading only specified BTF files..."
git sparse-checkout reapply || die "failed to apply sparse checkout"
git checkout || die "failed to checkout files"

cd -

info "Sparse checkout completed - downloaded only supported kernels for ${ARCH}"

# Change to btfhub directory to run btfgen.sh
cd "${BTFHUB_DIR}"

btfgen="./tools/btfgen.sh"

# Generate tailored BTFs
[ ! -f "${btfgen}" ] && die "could not find ${btfgen}"

# Create custom-archive directory to comply with btfgen.sh
mkdir -p ./custom-archive

# Get number of CPUs
if command -v nproc > /dev/null 2>&1; then
    NPROC=$(nproc)
elif [ -f /proc/cpuinfo ]; then
    NPROC=$(grep -c ^processor /proc/cpuinfo)
else
    NPROC=1
fi
# Fallback to 1 if detection failed or result is empty/non-numeric
if ! [ "${NPROC}" -ge 1 ] 2> /dev/null; then
    NPROC=1
fi

# Calculate optimal number of parallel jobs
if [ "${NPROC}" -le 2 ]; then
    JOBS="${NPROC}" # Use all cores on small systems - prioritize BTF tailoring completion
elif [ "${NPROC}" -le 4 ]; then
    JOBS=$((NPROC - 1)) # Reserve 1 core on medium systems
else
    JOBS=$((NPROC - 2)) # Reserve 2 cores on larger systems
fi

info "Generating tailored BTFs using ${JOBS} parallel jobs..."
${btfgen} -a "${ARCH}" -o "${TRACEE_BPF_CORE}" -j "${JOBS}"

# Move tailored BTFs to dist
[ ! -d "${BASEDIR}/dist" ] && die "could not find dist directory"
[ ! -d "${BASEDIR}/dist/btfhub" ] && mkdir "${BASEDIR}/dist/btfhub"

rm -rf "${BASEDIR}/dist/btfhub"/* || true
mv ./custom-archive/* "${BASEDIR}/dist/btfhub"

info "Tailored BTFs generated and moved to ${BASEDIR}/dist/btfhub"
