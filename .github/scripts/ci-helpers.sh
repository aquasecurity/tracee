#!/bin/sh
#
# Reusable helpers for GitHub Actions workflows.
# Source this file in a step, then call the helpers as needed.
#
# Usage (in a workflow step):
#   . .github/scripts/ci-helpers.sh
#   GH_REPO="${GITHUB_REPOSITORY}"  # or owner/repo
#   ensure_label "my-label" "ededed" "Description"
#   add_label "${PR_NUMBER}" "my-label"
#   remove_label "${PR_NUMBER}" "stale-label"
#
# Label helpers require GH_REPO and GH_TOKEN in the environment.
#

# URL-encode a label name for DELETE /issues/{n}/labels/{name}.
# Arguments:
#   $1 - label name
encode_label() {
    if command -v jq > /dev/null 2>&1; then
        printf '%s' "$1" | jq -sRr @uri
    else
        # Best-effort fallback if jq is unavailable.
        printf '%s' "$1" \
            | sed -e 's|%|%25|g' \
                -e 's| |%20|g' \
                -e 's|/|%2F|g'
    fi
}

# Create a repo label if it does not exist (422 is ignored).
# Arguments:
#   $1 - label name
#   $2 - color (hex, no #)
#   $3 - description
ensure_label() {
    err_file="$(mktemp)"

    if gh api --method POST "repos/${GH_REPO}/labels" \
        -f "name=$1" \
        -f "color=$2" \
        -f "description=$3" \
        > "${err_file}" 2>&1; then
        rm -f "${err_file}"
        return 0
    fi

    # Ignore 422 only when the error code is "already_exists".
    # Other 422s (invalid field, rate limit, auth) are real failures.
    if grep -q '"already_exists"' "${err_file}"; then
        rm -f "${err_file}"
        return 0
    fi

    echo "::warning::Failed to ensure label $1." >&2
    if [ -s "${err_file}" ]; then
        cat "${err_file}" >&2
    fi
    rm -f "${err_file}"
    return 1
}

# Add a label to an issue or PR (same REST endpoint).
# Arguments:
#   $1 - issue/PR number
#   $2 - label name
add_label() {
    gh api --method POST "repos/${GH_REPO}/issues/$1/labels" \
        -f "labels[]=$2" \
        --silent 2> /dev/null \
        || echo "::warning::Failed to add label $2 on #$1."
}

# Remove a label from an issue or PR.
# Arguments:
#   $1 - issue/PR number
#   $2 - label name
remove_label() {
    gh api --method DELETE \
        "repos/${GH_REPO}/issues/$1/labels/$(encode_label "$2")" \
        --silent 2> /dev/null || true
}
