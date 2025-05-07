#!/bin/sh
# Verifies that corresponding .1.md and .1 files have been updated together

set -e

# shellcheck disable=SC1091
. "${0%/*}/lib.sh"

# requirements for print_help
require_cmds cat

# default configuration
BASE_REF=""
BASE_REMOTE="origin"
BASE_BRANCH="main"
TARGET_REF="HEAD"
FETCH_DEPTH=""
FORCE_FETCH=0

# help text
print_help() {
    cat <<EOF
Usage: $0 [OPTIONS]

Checks whether '.1.md' and '.1' documentation files have been updated together
between two Git references (branches, tags, or commit SHAs).

Options:
  --base-ref        <ref>     Full Git reference to diff from (e.g. tag, SHA, or origin/main).
  --base-remote     <remote>  Remote to fetch from (default: origin).
  --base-branch     <branch>  Branch to fetch from remote (default: main).
  -t, --target-ref  <ref>     Git target ref to compare to (default: HEAD).
      --fetch-depth <n>       Optional: pass --depth=n to 'git fetch'.
      --fetch                 Force fetching even if no other fetch triggers apply.
  -h, --help                  Show this help message and exit.

Examples:
  $0
  $0 --base-ref v1.2.0 --target-ref HEAD
  $0 --base-remote origin --base-branch release/v1 --fetch-depth 1
  $0 --fetch
EOF
}

# parse arguments
while [ "$#" -gt 0 ]; do
    case "$1" in
    --base-ref)
        shift
        BASE_REF="$1"
        ;;
    --base-remote)
        shift
        BASE_REMOTE="$1"
        ;;
    --base-branch)
        shift
        BASE_BRANCH="$1"
        ;;
    -t | --target-ref)
        shift
        TARGET_REF="$1"
        ;;
    --fetch-depth)
        shift
        FETCH_DEPTH="$1"
        ;;
    --fetch)
        FORCE_FETCH=1
        ;;
    -h | --help)
        print_help
        exit 0
        ;;
    *) die "Unknown argument: $1" ;;
    esac
    shift
done

if [ -z "$BASE_REF" ]; then
    BASE_REF="$BASE_REMOTE/$BASE_BRANCH"
fi

require_cmds git basename grep sed xargs

print_script_start "Comparing changes from $BASE_REF to $TARGET_REF"

# determine whether to fetch
FETCH_NEEDED=0
[ -n "$FETCH_DEPTH" ] && FETCH_NEEDED=1
[ "$FORCE_FETCH" -eq 1 ] && FETCH_NEEDED=1

# conditional fetch
if [ "$FETCH_NEEDED" -eq 1 ]; then
    [ -n "$FETCH_DEPTH" ] && depth_arg="--depth=$FETCH_DEPTH" || depth_arg=""
    info "Fetching '$BASE_BRANCH' from '$BASE_REMOTE'${depth_arg:+ with $depth_arg}"
    git fetch "$BASE_REMOTE" "$BASE_BRANCH" "$depth_arg"
fi

# perform git diff
md_files=$(git diff --name-only "$BASE_REF..$TARGET_REF" -- 'docs/docs/flags/*.1.md')
man_files=$(git diff --name-only "$BASE_REF..$TARGET_REF" -- 'docs/man/*.1')

# extract basenames
md_basenames=$(echo "$md_files" | xargs -n 1 basename 2>/dev/null | sed 's/\.1\.md$//')
man_basenames=$(echo "$man_files" | xargs -n 1 basename 2>/dev/null | sed 's/\.1$//')

# validate consistency
missing_updates=""

for name in $md_basenames; do
    echo "$man_basenames" | grep -qx "$name" || missing_updates="${missing_updates}${name}.1.md change requires corresponding ${name}.1 change
"
done

for name in $man_basenames; do
    echo "$md_basenames" | grep -qx "$name" || missing_updates="${missing_updates}${name}.1 change requires corresponding ${name}.1.md change
"
done

if [ -n "$missing_updates" ]; then
    error "Documentation Mismatch"

    old_ifs="$IFS"
    IFS='
'
    for line in $missing_updates; do
        [ -n "$line" ] && error " - $line"
    done
    IFS="$old_ifs"

    error

    error "How to Fix It"
    error " 1. Modify only '.1.md' files, updating the date if needed."
    error " 2. Run 'make -f builder/Makefile.man man-run' to regenerate '.1' files."

    exit 1
fi

info "Documentation files are consistent."
