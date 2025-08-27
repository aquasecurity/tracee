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

# print_help displays usage information.
# Usage:
#   print_help
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
    *)
        die "Unknown argument: $1"
        ;;
    esac
    shift
done

#
# script start
#

require_cmds git basename grep sed xargs || die "Missing required commands"

[ -z "$BASE_REF" ] && BASE_REF="$BASE_REMOTE/$BASE_BRANCH"

print_script_start "Comparing changes from $BASE_REF to $TARGET_REF" || die "Failed to start script"

# conditional fetch
if [ -n "$FETCH_DEPTH" ] || [ "$FORCE_FETCH" -eq 1 ]; then
    [ -n "$FETCH_DEPTH" ] && depth_arg="--depth=$FETCH_DEPTH" || depth_arg=""
    info "Fetching '$BASE_BRANCH' from '$BASE_REMOTE'${depth_arg:+ with $depth_arg}"
    git fetch "$BASE_REMOTE" "$BASE_BRANCH" "$depth_arg" || die "Failed to fetch $BASE_BRANCH from $BASE_REMOTE"
fi

flags_md_files=$(git_changed_files "$BASE_REF" "$TARGET_REF" 'docs/docs/flags/*.1.md') || die "Failed to get flags md changed files"
events_md_files=$(git_changed_files "$BASE_REF" "$TARGET_REF" 'docs/docs/events/builtin/man/**/*.md') || die "Failed to get events md changed files"
man_files=$(git_changed_files "$BASE_REF" "$TARGET_REF" 'docs/man/*.1') || die "Failed to get man changed files"

# Combine flags and events md files
md_files="$flags_md_files"
if [ -n "$events_md_files" ]; then
    if [ -n "$md_files" ]; then
        md_files="$md_files
$events_md_files"
    else
        md_files="$events_md_files"
    fi
fi

if [ -z "$md_files" ]; then
    info "No changes in '.md' or '.1.md' files"
else
    info "Found changes in '.md' or '.1.md' files"
    # Extract basenames from both flags (.1.md) and events (.md) files
    flags_basenames=""
    events_basenames=""
    if [ -n "$flags_md_files" ]; then
        flags_basenames=$(basename_strip_ext "$flags_md_files" '1.md') || die "Failed to get flags basenames"
    fi

    if [ -n "$events_md_files" ]; then
        events_basenames=$(basename_strip_ext "$events_md_files" 'md') || die "Failed to get events basenames"
    fi

    # Combine all basenames
    md_basenames="$flags_basenames"
    if [ -n "$events_basenames" ]; then
        if [ -n "$md_basenames" ]; then
            md_basenames="$md_basenames
$events_basenames"
        else
            md_basenames="$events_basenames"
        fi
    fi
fi

if [ -z "$man_files" ]; then
    info "No changes in '.1' files"
else
    info "Found changes in '.1' files"
    man_basenames=$(basename_strip_ext "$man_files" '1') || die "Failed to get man basenames"
fi

missing_updates=$(list_diff "$md_basenames" "$man_basenames") || die "Failed to get missing updates"

if [ -n "$missing_updates" ]; then
    error "Documentation Mismatch"

    printf "%s\n" "$missing_updates" | while IFS= read -r file; do
        [ -n "$file" ] || continue # skip empty lines
        error " - $file source change requires corresponding $file.1 change"
    done

    error

    error "How to Fix It"
    error " 1. Modify source files (flags: '.1.md', events: '.md'), updating the date if needed."
    error " 2. Run 'make man' to regenerate '.1' files."

    exit 1
fi

info "Documentation files are consistent."
