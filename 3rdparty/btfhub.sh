#!/bin/bash -e

# This script downloads & updates 2 repos inside tracee dir structure:
#
#     1) ./3rdparty/btfhub-archive
#     2) ./3rdparty/btfhub
#
# It uses the 2 repositories to generate tailored BTF files, according to
# latest CO-RE object file, so those files can be embedded in tracee Go binary.
#
# Note: You may opt out from fetching repositories changes in the beginning of
# the execution by exporting SKIP_FETCH=1 env variable.

BASEDIR=$(dirname "${0}")
cd ${BASEDIR}/../
BASEDIR=$(pwd)
cd ${BASEDIR}

# variables

BTFHUB_REPO="https://github.com/aquasecurity/btfhub.git"
BTFHUB_ARCH_REPO="https://github.com/aquasecurity/btfhub-archive.git"

TRACEE_BPF_CORE="${BASEDIR}/dist/tracee.bpf.o"

BTFHUB_DIR="${BASEDIR}/3rdparty/btfhub"
BTFHUB_ARCH_DIR="${BASEDIR}/3rdparty/btfhub-archive"

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

die() {
    echo ${@}
    exit 1
}

branch_clean() {
    cd ${1} || die "could not change dirs"

    # small sanity check
    [ ! -d ./.git ] && die "$(basename $(pwd)) not a repo dir"

    git fetch -a || die "could not fetch ${1}" # make sure its updated
    git clean -fdX                             # clean leftovers
    git reset --hard                           # reset letfovers
    git checkout origin/main -b main-$$
    git branch -D main
    git branch -m main-$$ main # origin/main == main

    cd ${BASEDIR}
}

# requirements

CMDS="rsync git cp rm mv"
for cmd in ${CMDS}; do
    command -v $cmd 2>&1 >/dev/null || die "cmd ${cmd} not found"
done

[ ! -f ${TRACEE_BPF_CORE} ] && die "tracee CO-RE obj not found"

[ ! -d ${BTFHUB_DIR} ] && git clone "${BTFHUB_REPO}" ${BTFHUB_DIR}
[ ! -d ${BTFHUB_ARCH_DIR} ] && git clone "${BTFHUB_ARCH_REPO}" ${BTFHUB_ARCH_DIR}

if [ -z ${SKIP_FETCH} ]; then
    branch_clean ${BTFHUB_DIR}
    branch_clean ${BTFHUB_ARCH_DIR}
fi

cd ${BTFHUB_DIR}

# sync only supported kernels

ARCH_EXCLUDE=$(printf "x86_64\naarch64\n" | grep -v $(uname -m) | xargs)

rsync -avz \
    ${BTFHUB_ARCH_DIR}/ \
    --exclude=.git* \
    --exclude=README.md \
    --exclude=${ARCH_EXCLUDE} \
    --exclude=*/3.* \
    --exclude=*/4.* \
    ./archive/

# sync v4.18 kernels for RHEL only (eBPF features backported)

for n in rhel centos; do
    rsync -avz \
        ${BTFHUB_ARCH_DIR}/$n/8/* \
        --exclude=${ARCH_EXCLUDE} \
        ./archive/$n/8/
done

# generate tailored BTFs

[ ! -f ./tools/btfgen.sh ] && die "could not find btfgen.sh"
./tools/btfgen.sh -a ${ARCH} -o ${TRACEE_BPF_CORE}

# move tailored BTFs to dist

[ ! -d ${BASEDIR}/dist ] && die "could not find dist directory"
[ ! -d ${BASEDIR}/dist/btfhub ] && mkdir ${BASEDIR}/dist/btfhub

rm -rf ${BASEDIR}/dist/btfhub/* || true
mv ./custom-archive/* ${BASEDIR}/dist/btfhub
