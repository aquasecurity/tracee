#!/bin/bash

# script responsible for building fedora packages

syntax() {
	echo "$0 [bin|src] [version]"
	exit 1
}

die() {
	echo $1
	exit 1
}

. /etc/os-release

# if [ "${ID}" != "fedora" ]; then
# 	die "you must use a fedora linux to run this script"
# fi

current_dir=$(basename $(pwd))
[[ "${current_dir}" == "builder" || "${current_dir}" == "packaging" ]] && \
	die "you must be in root directory"

date=$(date -u +%y%m%d%H%M)
tracee_commit=$(git log --format="%h" -n1)
tracee_version=$(git describe --tags --match 'v*' 2>/dev/null)

cmd=$1
version=$2

if [[ "${cmd}" == "" || "${version}" == "" ]]; then
	syntax
fi

export GOROOT=/usr/local/go
export GOPATH=/home/tracee/go
export PATH=/usr/local/go/bin:$PATH

fedora_ver_prefix=$(echo -n ${tracee_version} | cut -d'-' -f1,2 | sed 's:v::g' | sed 's:-:\.:g')
fedora_ver_suffix=$(echo f${version}.${date}.${tracee_commit})

find ./packaging/ -type f -name tracee.spec -exec cp {} . \;

sed -i "s:VERSION:${fedora_ver_prefix}:g" ./tracee.spec
sed -i "s:RELEASE:${fedora_ver_suffix}:g" ./tracee.spec

rpmbuild --build-in-place -bb ./tracee.spec

mv ~/rpmbuild/RPMS/$(uname -m)/*.rpm ./dist

rm ./tracee.spec
