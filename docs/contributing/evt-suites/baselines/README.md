# Performance Gate Baselines

This directory contains per-arch per-scenario baseline files used by the
performance gate to detect regressions.

## File naming

```
<arch>-<scenario>.json
```

For example: `x86_64-smoke.json`, `aarch64-security.json`.

## File format

Each baseline file contains the KPIs from a validated run:

```json
{
  "peak_rss_kb": 123456,
  "avg_cpu_pct": 45.2,
  "p95_cpu_pct": 72.1,
  "updated_at": "2026-02-25T12:00:00Z",
  "commit_sha": "abc123def456",
  "notes": "Reason for this baseline update"
}
```

## How baselines are used

The script `run-evt-stress-with-collection.sh` loads the baseline matching
the current architecture and scenario. Each gated KPI is compared with a
tolerance:

| Metric | Tolerance |
| --- | --- |
| `peak_rss_kb` | +20% |
| `avg_cpu_pct` | +25% |
| `p95_cpu_pct` | +25% |

If any metric exceeds its tolerance the gate fails.

When no baseline file exists the comparison is skipped with a warning and
the gate passes (bootstrap path).

## Updating baselines

After a validated run on `main` (or a release tag), update the baseline:

1. Copy the relevant values from the run's `summary.json` into the
   baseline file.
2. Set `updated_at` to the current timestamp.
3. Set `commit_sha` to the commit that produced the run.
4. Add a `notes` field explaining why the baseline changed.
5. Commit the updated baseline file.
