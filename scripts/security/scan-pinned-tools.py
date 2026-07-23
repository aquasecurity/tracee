#!/usr/bin/env python3
"""
Scan version-pinned tools that Trivy cannot see (hand-unpacked / source-built
binaries) against a CVE database, using the versions we already pin.

Two modes:
  --verify   Drift check only: assert every manifest 'match' string is present in
             its 'source' file. Fast, offline, safe to gate PRs on.
  (default)  Verify, then query OSV (and NVD for 'cpe' entries) for known vulns.

Each finding is reported with the 'source' file that owns the pin, so a CVE can be
traced straight back to the file to bump. When GITHUB_STEP_SUMMARY is set, a markdown
findings table is appended to the job summary.

Reads scripts/security/pinned-tools.json. Standard library only.

Exit codes: 0 = clean, 1 = vulnerabilities found, 2 = drift / manifest error.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MANIFEST = os.path.join(ROOT, "scripts", "security", "pinned-tools.json")

OSV_URL = "https://api.osv.dev/v1/query"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Optional: set NVD_API_KEY to raise the anonymous rate limit (5 req / 30s).
NVD_KEY = os.environ.get("NVD_API_KEY", "")


def load_tools():
    with open(MANIFEST) as fh:
        data = json.load(fh)
    return [t for t in data.get("tools", []) if not t.get("_disabled")]


def verify_drift(tools):
    """Ensure each manifest entry still matches the real pin in its source file."""
    problems = []
    for t in tools:
        match, source = t.get("match"), t.get("source")
        if not match or not source:
            continue  # entries without a concrete pin (e.g. bpftool) are informational
        path = os.path.join(ROOT, source)
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                if match not in fh.read():
                    problems.append(f"{t['name']}: '{match}' not found in {source} (pin drifted?)")
        except FileNotFoundError:
            problems.append(f"{t['name']}: source file not found: {source}")
    return problems


def query_osv(ecosystem, name, version):
    body = json.dumps({"version": version, "package": {"ecosystem": ecosystem, "name": name}}).encode()
    req = urllib.request.Request(OSV_URL, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        vulns = json.load(resp).get("vulns", [])
    return [v.get("id", "?") for v in vulns]


def query_nvd(cpe):
    url = f"{NVD_URL}?cpeName={urllib.parse.quote(cpe)}"
    headers = {"apiKey": NVD_KEY} if NVD_KEY else {}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        items = json.load(resp).get("vulnerabilities", [])
    if not NVD_KEY:
        time.sleep(6)  # stay under the anonymous rate limit
    return [i["cve"]["id"] for i in items]


def scan(tools):
    """Query each tool; return a list of result rows (with source file and CVE ids)."""
    results = []
    for t in tools:
        ident = t.get("osv") or ({"cpe": t["cpe"]} if t.get("cpe") else None)
        if not ident:
            continue
        try:
            if "cpe" in ident:
                ids = query_nvd(ident["cpe"])
            else:
                ids = query_osv(ident["ecosystem"], ident["name"], t["version"])
        except (urllib.error.URLError, KeyError, ValueError) as e:
            print(f"  ! {t['name']}: query failed ({e})", file=sys.stderr)
            ids = None
        results.append(
            {"name": t["name"], "version": t["version"], "source": t.get("source", "?"), "ids": ids}
        )
        loc = f" [{t.get('source', '?')}]"
        if ids is None:
            status = "query failed"
        elif ids:
            status = ", ".join(ids)
        else:
            status = "clean"
        print(f"  {t['name']} {t['version']}{loc}: {status}")
    return results


def render_summary(results):
    lines = ["## Pinned Hand-Unpacked Tools (OSV / NVD)", ""]
    if not results:
        lines.append("_No queryable entries in the manifest._")
        return "\n".join(lines) + "\n"
    lines += ["| Tool | Version | Pinned in | Findings |", "|------|---------|-----------|----------|"]
    for r in results:
        if r["ids"] is None:
            found = "query failed"
        elif r["ids"]:
            found = ", ".join(r["ids"])
        else:
            found = "clean"
        lines.append(f"| {r['name']} | `{r['version']}` | `{r['source']}` | {found} |")
    lines.append("")
    return "\n".join(lines) + "\n"


def emit_step_summary(markdown):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(markdown)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true", help="drift check only, no network")
    args = ap.parse_args()

    tools = load_tools()

    drift = verify_drift(tools)
    if drift:
        print("DRIFT / manifest errors:", file=sys.stderr)
        for d in drift:
            print(f"  - {d}", file=sys.stderr)
        return 2
    print(f"verify: {len(tools)} entries consistent with their source files")
    if args.verify:
        return 0

    results = scan(tools)
    emit_step_summary(render_summary(results))

    vulnerable = [r for r in results if r["ids"]]
    if vulnerable:
        print(f"\n{len(vulnerable)} tool(s) with known vulnerabilities:", file=sys.stderr)
        for r in vulnerable:
            print(f"  - {r['name']} {r['version']} (pinned in {r['source']}): {', '.join(r['ids'])}", file=sys.stderr)
        return 1
    print("\nNo known vulnerabilities for pinned hand-unpacked tools.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
