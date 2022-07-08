#!/bin/bash

# script responsible for building ubuntu packages

syntax() {
	echo "$0 [bin|src] [series]"
	exit 1
}

die() {
	echo $1
	exit 1
}

. /etc/os-release

if [ "${ID}" != "ubuntu" ]; then
	die "you must use an ubuntu linux to run this script"
fi

current_dir=$(basename $(pwd))
[[ "${current_dir}" == "builder" || "${current_dir}" == "packaging" ]] && \
	die "you must be in root directory"

date=$(date -u +%y%m%d%H%M)
last_commit=$(git log --format="%h" -n1)
last_git_tag=$(git describe --tags --match 'v*' 2>/dev/null)

cmd=$1
series=$2

if [[ "${cmd}" == "" || "${series}" == "" ]]; then
	syntax
fi

distro-info --series=${series} -r > /dev/null 2>&1
if [ $? -eq 1 ]; then
	die "unsupported ubuntu version: ${series}"
fi

series_ver=$(distro-info --series=${series} -r | cut -d' ' -f1)
deb_ver_prefix=$(echo -n ${last_git_tag} | cut -d'-' -f1,2 | sed 's:v::g')
deb_ver_suffix=$(echo ${date}-${last_commit})
deb_version=${deb_ver_prefix}~${series_ver}~${deb_ver_suffix}

rm -rf ./debian/
find ./packaging/ -type d -name ubuntu -exec cp -r {} ./debian \;

sed -i "s:VERSION:${deb_version}:g" ./debian/changelog
sed -i "s:SERIES:${series}:g" ./debian/changelog
sed -i "s:DESCRIPTION:Tracee ${last_git_tag} (built on ${date}):g" ./debian/changelog

export DEB_BUILD_OPTIONS="nocheck nostrip noudeb doc"

#
# TODO: add src cmd to generate source packages. src packages will only work
# from impish and beyond (due to build depends). with src packages we're able
# to submit them to ubuntu builders and have them added to universe archive.
#

if [ "${KEY}" == "" ]; then
	dpkg-buildpackage -b -uc -us
else
	dpkg-buildpackage -b -k${KEY}
fi

[ ! -d ./dist ] && mkdir ./dist

mv ../*.deb ./dist/
rm -rf ./debian/
