#!/usr/bin/env bash
# Regression for aquasecurity/tracee#5387:
# Rendered Tracee config must use keys the chart's pinned image (appVersion /
# Tracee 0.24.1) understands: server.http-address, log, output.<format>.files.
# Legacy listen-addr / top-level healthz / metrics leave readiness on :3366 failing.
# Unreleased main keys (logging, output.destinations) must not appear while the
# chart still defaults to the 0.24.1 image.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "$root/../../.." && pwd)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

helm template tracee "$root" > "$tmpdir/all.yaml"

python3 - "$tmpdir/all.yaml" "$tmpdir/config.yaml" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
lines = open(src).read().splitlines()
# Find the ConfigMap named tracee-config, then its config.yaml literal block.
in_cm = False
in_payload = False
payload = []
for i, line in enumerate(lines):
    if line.startswith("kind: ConfigMap"):
        # look ahead for name
        window = "\n".join(lines[i:i+15])
        in_cm = "name: tracee-config" in window
        in_payload = False
        continue
    if not in_cm:
        continue
    if line.startswith("  config.yaml: |-"):
        in_payload = True
        continue
    if in_payload:
        if line.startswith("    "):
            payload.append(line[4:])
            continue
        # end of literal block
        break
if not payload:
    sys.exit("could not find tracee-config ConfigMap payload")
open(dst, "w").write("\n".join(payload) + "\n")
PY

cfg="$tmpdir/config.yaml"
echo "---- rendered config.yaml ----"
cat "$cfg"
echo "---- assertions ----"

fail=0
require() {
  local pat="$1" msg="$2"
  if ! grep -Eq "$pat" "$cfg"; then
    echo "FAIL: $msg (/$pat/)" >&2
    fail=1
  else
    echo "OK: $msg"
  fi
}
forbid() {
  local pat="$1" msg="$2"
  if grep -Eq "$pat" "$cfg"; then
    echo "FAIL: $msg (/$pat/ matched)" >&2
    fail=1
  else
    echo "OK: $msg"
  fi
}

require '^[[:space:]]*http-address:' 'server.http-address is present'
require '^log:' 'top-level log key is present (Tracee 0.24.1 GetFlagsFromViper("log"))'
require '^[[:space:]]*healthz:[[:space:]]*true' 'healthz lives under server'
require '^[[:space:]]*json:' 'output.json is present'
require '^[[:space:]]*files:' 'output.<format>.files is present'
forbid '^listen-addr:' 'legacy listen-addr must not appear'
forbid '^logging:' 'unreleased logging key must not appear while image is 0.24.1'
forbid '^[[:space:]]*destinations:' 'unreleased output.destinations must not appear while image is 0.24.1'
forbid '^healthz:' 'legacy top-level healthz must not appear'
forbid '^metrics:' 'legacy top-level metrics must not appear'
forbid '^perf-buffer-size:' 'legacy perf-buffer-size must not appear'

static="$repo/deploy/kubernetes/tracee/tracee.yaml"
if [[ -f "$static" ]]; then
  echo "---- static manifest $static ----"
  if ! grep -q 'http-address:' "$static"; then echo "FAIL static: missing http-address" >&2; fail=1; else echo "OK static: has http-address"; fi
  if ! grep -Eq '^[[:space:]]*log:' "$static"; then echo "FAIL static: missing log key" >&2; fail=1; else echo "OK static: has log key"; fi
  if grep -Eq '^[[:space:]]*logging:' "$static"; then echo "FAIL static: has unreleased logging key" >&2; fail=1; else echo "OK static: no logging key"; fi
  if grep -q 'destinations:' "$static"; then echo "FAIL static: has destinations" >&2; fail=1; else echo "OK static: no destinations"; fi
  if ! grep -q 'files:' "$static"; then echo "FAIL static: missing output files" >&2; fail=1; else echo "OK static: has output files"; fi
  if grep -q 'listen-addr:' "$static"; then echo "FAIL static: has listen-addr" >&2; fail=1; else echo "OK static: no listen-addr"; fi
else
  echo "WARN: static manifest not found at $static" >&2
fi

exit "$fail"
