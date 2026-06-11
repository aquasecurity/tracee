#!/bin/bash
set -euo pipefail

mode="${1:-staged}"
diff_range="${2:-}"

status=0
while IFS= read -r f; do
    case "${f}" in
        3rdparty/* | dist/* | .git/*) continue ;;
    esac
    if [ -n "${f}" ] && [ -f "${f}" ]; then
        rg_output="$(rg -n "[^\x09\x0A\x20-\x7E]" -- "${f}")" || rg_status=$?
        rg_status="${rg_status:-0}"
        case "${rg_status}" in
            0)
                printf '%s\n' "${rg_output}"
                status=1
                ;;
            1)
                ;;
            *)
                echo "rg failed while checking ${f}" >&2
                exit "${rg_status}"
                ;;
        esac
        unset rg_status
    fi
done < <(
    if [ "${mode}" = "staged" ]; then
        git diff --cached --diff-filter=ACMR --name-only
    elif [ "${mode}" = "diff" ]; then
        if [ -z "${diff_range}" ]; then
            echo "Usage: .cursor/hooks/ascii-check-changed.sh diff BASE..HEAD" >&2
            exit 1
        fi
        git diff "${diff_range}" --diff-filter=ACMR --name-only
    else
        echo "Usage: .cursor/hooks/ascii-check-changed.sh [staged|diff BASE..HEAD]" >&2
        exit 1
    fi
)

exit ${status}
