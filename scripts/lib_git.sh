#!/bin/sh

#
# git
#

__LIB_GIT_NAME="lib_git.sh"

# prevent multiple sourcing
if [ -n "${__LIB_GIT_SH_SOURCED}" ]; then
    return 0
fi
__LIB_GIT_SH_SOURCED=1

# must be sourced, not executed
case "${0##*/}" in
    "${__LIB_GIT_NAME}")
        printf "[%s]: %s\n" "${__LIB_GIT_NAME}" "This script must be sourced, not executed."
        exit 1
        ;;
esac

############
# functions
############

# git_changed_files lists filenames changed between two refs matching the given pattern.
#
# $1: REF1 - Base git reference for comparison.
# $2: REF2 - Target git reference for comparison.
# $3: PATTERN - File pattern to filter git diff results.
#
# Usage:
#   git_changed_files REF1 REF2 PATTERN
#
# Example:
#   git_changed_files HEAD~2 HEAD 'path/*.md'
#
# Output:
#   path/file1.md
#   path/file2.md
git_changed_files() {
    git_changed_files_ref1="$1"
    git_changed_files_ref2="$2"
    git_changed_files_pattern="$3"
    if [ -z "${git_changed_files_ref1}" ]; then
        __error "git_changed_files: No REF1 provided"
        return 1
    fi
    if [ -z "${git_changed_files_ref2}" ]; then
        __error "git_changed_files: No REF2 provided"
        return 1
    fi
    if [ -z "${git_changed_files_pattern}" ]; then
        __error "git_changed_files: No PATTERN provided"
        return 1
    fi

    # step 1: get changed files
    git_changed_files_step1=$(git diff --name-only "${git_changed_files_ref1}..${git_changed_files_ref2}" -- "${git_changed_files_pattern}") || {
        __status=$?
        __error "git_changed_files: git diff failed"
        return ${__status}
    }

    # step 2: sanitize to lines
    git_changed_files_result=$(printf "%s\n" "${git_changed_files_step1}" | xargs -n1) || {
        __status=$?
        __error "git_changed_files: xargs sanitize failed"
        return ${__status}
    }

    printf "%s\n" "${git_changed_files_result}"
}
