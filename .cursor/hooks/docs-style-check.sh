#!/bin/bash
set -euo pipefail

if ! command -v jq > /dev/null 2>&1; then
    # Fail open so missing local dependency does not block edits.
    echo '{ "permission": "allow" }'
    exit 0
fi

input="$(cat)"
if ! file_path="$(printf '%s' "${input}" | jq -r '.arguments.path // .arguments.filePath // empty')"; then
    # Fail open on malformed/unexpected input payloads.
    echo '{ "permission": "allow" }'
    exit 0
fi

if [[ ! "${file_path}" =~ \.md$ ]]; then
    echo '{ "permission": "allow" }'
    exit 0
fi

echo '{
  "permission": "ask",
  "user_message": "You are editing markdown docs. Ensure policy text aligns with canonical project sources, uses must/should/may consistently, and keeps guidance concise.",
  "agent_message": "Docs style check triggered for markdown edit."
}'
exit 0
