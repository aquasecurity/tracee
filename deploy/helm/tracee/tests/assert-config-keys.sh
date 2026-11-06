#!/usr/bin/env bash
# Regression for aquasecurity/tracee#5387:
# Rendered Tracee config must use keys the chart's pinned image (appVersion /
# Tracee 0.24.1) understands: server.http-address, log, output.<format>.files,
# and output.options.parse-arguments (mapped from enrichment.decoded-data).
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

# Path-aware YAML checks so renaming server:/output: to an unrecognized parent fails.
if ! python3 - "$cfg" <<'PY'
import sys
try:
    import yaml
except ImportError:
    # PyYAML may be absent; fall back to a tiny subset parser via safe_load alternative
    print("FAIL: PyYAML is required for path assertions", file=sys.stderr)
    sys.exit(1)

cfg_path = sys.argv[1]
doc = yaml.safe_load(open(cfg_path))
fail = 0

def ok(msg):
    print(f"OK: {msg}")

def bad(msg):
    global fail
    print(f"FAIL: {msg}", file=sys.stderr)
    fail = 1

def dig(obj, *keys):
    cur = obj
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur

if not isinstance(doc, dict):
    bad("config root must be a mapping")
    sys.exit(1)

http_addr = dig(doc, "server", "http-address")
if not http_addr:
    bad("server.http-address must be set")
else:
    ok(f"server.http-address={http_addr!r}")

healthz = dig(doc, "server", "healthz")
if healthz is not True:
    bad(f"server.healthz must be true, got {healthz!r}")
else:
    ok("server.healthz is true")

if "log" not in doc or not isinstance(doc["log"], dict):
    bad("top-level log mapping is required (Tracee 0.24.1 GetFlagsFromViper(\"log\"))")
else:
    ok("top-level log key is present")

if "logging" in doc:
    bad("unreleased logging key must not appear while image is 0.24.1")
else:
    ok("no unreleased logging key")

files = dig(doc, "output", "json", "files")
if not files:
    bad("output.json.files must be present")
else:
    ok(f"output.json.files={files!r}")

if dig(doc, "output", "destinations") is not None:
    bad("unreleased output.destinations must not appear while image is 0.24.1")
else:
    ok("no output.destinations")

parse_args = dig(doc, "output", "options", "parse-arguments")
decoded = dig(doc, "enrichment", "decoded-data")
if decoded is True and parse_args is not True:
    bad(f"output.options.parse-arguments must mirror enrichment.decoded-data=true, got {parse_args!r}")
elif decoded is False and parse_args not in (False, None):
    bad(f"output.options.parse-arguments should be false when decoded-data is false, got {parse_args!r}")
elif parse_args is True:
    ok("output.options.parse-arguments is true (from enrichment.decoded-data)")
else:
    ok(f"output.options.parse-arguments={parse_args!r}")

# Legacy keys that break readiness / buffers
for legacy in ("listen-addr", "healthz", "metrics", "perf-buffer-size"):
    if legacy in doc:
        bad(f"legacy top-level {legacy} must not appear")
    else:
        ok(f"no legacy top-level {legacy}")

sys.exit(fail)
PY
then
  fail=1
fi

static="$repo/deploy/kubernetes/tracee/tracee.yaml"
if [[ -f "$static" ]]; then
  echo "---- static manifest $static ----"
  if ! python3 - "$static" <<'PY'
import sys
try:
    import yaml
except ImportError:
    print("FAIL: PyYAML is required for static path assertions", file=sys.stderr)
    sys.exit(1)

text = open(sys.argv[1]).read()
docs = list(yaml.safe_load_all(text))
payload = None
for doc in docs:
    if not isinstance(doc, dict):
        continue
    if doc.get("kind") != "ConfigMap":
        continue
    meta = doc.get("metadata") or {}
    if meta.get("name") != "tracee-config":
        continue
    raw = (doc.get("data") or {}).get("config.yaml")
    if raw is None:
        continue
    payload = yaml.safe_load(raw)
    break

fail = 0

def ok(msg):
    print(f"OK static: {msg}")

def bad(msg):
    global fail
    print(f"FAIL static: {msg}", file=sys.stderr)
    fail = 1

def dig(obj, *keys):
    cur = obj
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur

if not isinstance(payload, dict):
    bad("could not parse tracee-config ConfigMap payload")
    sys.exit(1)

if not dig(payload, "server", "http-address"):
    bad("missing server.http-address")
else:
    ok("has server.http-address")

if dig(payload, "server", "healthz") is not True:
    bad("server.healthz must be true")
else:
    ok("has server.healthz")

if "log" not in payload:
    bad("missing log key")
else:
    ok("has log key")

if "logging" in payload:
    bad("has unreleased logging key")
else:
    ok("no logging key")

if not dig(payload, "output", "json", "files"):
    bad("missing output.json.files")
else:
    ok("has output.json.files")

if dig(payload, "output", "destinations") is not None:
    bad("has destinations")
else:
    ok("no destinations")

if dig(payload, "output", "options", "parse-arguments") is not True:
    bad("missing output.options.parse-arguments=true")
else:
    ok("has output.options.parse-arguments")

if "listen-addr" in payload:
    bad("has listen-addr")
else:
    ok("no listen-addr")

sys.exit(fail)
PY
  then
    fail=1
  fi
else
  echo "WARN: static manifest not found at $static" >&2
fi

exit "$fail"
