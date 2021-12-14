#!/bin/bash

# This script downloads & updates 2 repos inside tracee dir structure:
#
#     1) ./3rdparty/btfhub-archive
#     2) ./3rdparty/btfhub
#
# It uses the 2 repositories to generate tailored BTF files, according to
# latest CO-RE object file, so those files can be embedded in tracee Go binary.

BASEDIR=$(dirname "${0}") ; cd ${BASEDIR}/../ ; BASEDIR=$(pwd) ; cd ${BASEDIR}

# variables

TRACEE_BPF_CORE="${BASEDIR}/dist/tracee.bpf.core.o"
BTFHUB_REPO="https://github.com/aquasecurity/btfhub.git"
BTFHUB_ARCH_REPO="https://github.com/aquasecurity/btfhub-archive.git"
BTFHUB_DIR="${BASEDIR}/3rdparty/btfhub"
BTFHUB_ARCH_DIR="${BASEDIR}/3rdparty/btfhub-archive"

ARCH=$(uname -m)

case ${ARCH} in
    "x86_64")
        ARCH="x86_64"
        NOT_ARCH=("arm64")
        ;;
    "aarch64")
        ARCH="arm64"
        NOT_ARCH=("x86_64")
        ;;
    *)
        die "unsupported architecture" ;;
esac

die() {
    echo ${@}
    exit 1
}

branch_clean() {
    cd ${1} || die "could not change dirs"

    # small sanity check
    [ ! -f ./README.md ] && die "$(basename $(pwd)) not a repo dir"

    git fetch -a || die "could not fetch ${1}"  # make sure its updated
    git clean -fdX                              # clean leftovers
    git reset --hard                            # reset letfovers
    git checkout origin/main -b main-$$
    git branch -D main
    git branch -m main-$$ main                  # origin/main == main

    cd ${BASEDIR}
}

[ ! -f ${TRACEE_BPF_CORE} ] && die "tracee CO-RE obj not found"

[ ! -d ${BTFHUB_DIR} ] && git clone "${BTFHUB_REPO}" ${BTFHUB_DIR}
[ ! -d ${BTFHUB_ARCH_DIR} ] && git clone "${BTFHUB_ARCH_REPO}" ${BTFHUB_ARCH_DIR}

branch_clean ${BTFHUB_DIR}
branch_clean ${BTFHUB_ARCH_DIR}

cd ${BTFHUB_DIR}

# only supported distros and kernels

rsync -avz \
    ${BTFHUB_ARCH_DIR}/                 \
    --exclude=.git*                     \
    --exclude=README.md                 \
    --exclude="centos/7*"               \
    --exclude="fedora/29/*/5.3*"        \
    --exclude="fedora/30/*/5.6*"        \
    --exclude="fedora/31*"              \
    --exclude="fedora/32*"              \
    --exclude="fedora/33*"              \
    --exclude="fedora/34*"              \
    --exclude="4.15*"                   \
    ./archive/

# cleanup unneeded architectures

for not in ${NOT_ARCH[@]}; do
    rm -r $(find ./archive/ -type d -name ${not} | xargs)
done

# generate tailored BTFs

[ ! -f ./tools/btfgen.sh ] && die "could not find btfgen.sh"
./tools/btfgen.sh -a ${ARCH} -o $TRACEE_BPF_CORE

# move tailored BTFs to dist

[ ! -d ${BASEDIR}/dist ] && die "could not find dist directory"
[ ! -d ${BASEDIR}/dist/btfhub ] && mkdir ${BASEDIR}/dist/btfhub

rm -rf ${BASEDIR}/dist/btfhub/*
mv ./custom-archive/* ${BASEDIR}/dist/btfhub
