#!/bin/sh

# Configure the container build-environment user and sudo policy.
#
# Creates a 'tracee' user matching the host uid/gid (passed as build args by
# 'make image') so files created in the bind-mounted source tree come out
# owned by the invoking host user. With uid 0 (e.g. CI runners building as
# root) the 'tracee' entry simply aliases root, so 'USER tracee' keeps
# working.
#
# usage: setup-buildenv-user.sh <uid> <gid>

set -e

# Source lib.sh for consistent logging and utilities
SCRIPT_DIR="${0%/*}"
__LIB_DIR="${SCRIPT_DIR}/.."
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

uid="${1:?usage: $0 <uid> <gid>}"
gid="${2:?usage: $0 <uid> <gid>}"

info "Setting up build environment user (uid=${uid} gid=${gid})"

# allow TRACEE* and LIBBPFGO* environment variables through sudo
cat > /etc/sudoers << EOF
Defaults env_keep += "LANG LC_* HOME EDITOR PAGER GIT_PAGER MAN_PAGER"
Defaults env_keep += "LIBBPFGO* TRACEE*"
root ALL=(ALL) NOPASSWD: ALL
tracee ALL=(ALL) NOPASSWD: ALL
EOF
chmod 0440 /etc/sudoers

# prepare tracee user to be uid:gid host equivalent
mkdir -p /home/tracee
echo "tracee:x:${uid}:${gid}:Tracee,,,:/home/tracee:/bin/bash" >> /etc/passwd
if ! getent group "${gid}" > /dev/null 2>&1; then
    echo "tracee:x:${gid}:" >> /etc/group
fi
echo "tracee::99999:0:99999:7:::" >> /etc/shadow

cat > /home/tracee/.bashrc << 'EOF'
export PS1="\u@\h[\w]$ "
alias ls="ls --color"
set -o vi
EOF
ln -sf /home/tracee/.bashrc /home/tracee/.profile
chown -R "${uid}:${gid}" /home/tracee

# the mounted source tree may be owned by a different uid than the one make
# runs as inside the container (docker without userns, sudo runs) - never
# treat that as a security problem for git operations
git config --system --add safe.directory /tracee 2> /dev/null \
    || git config --global --add safe.directory /tracee

info "Build environment user configured"
