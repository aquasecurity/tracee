# Filterability example policies

These policies each demonstrate one outcome of `tracee list filterable`, which reports where each
event's filtering happens: in the **kernel** (non-matching instances dropped before the event is
submitted - the cheapest filtering) or in **user space** (the kernel submits every instance, then
Tracee filters it).

Run any of them with:

```console
tracee list filterable <file-or-directory>
```

## Scenarios

| File | Reports | Why |
|------|---------|-----|
| `kernel-scope.yaml` | `[kernel] openat` | A policy `spec.scope` filter is pushed to the kernel. |
| `kernel-rule-scope.yaml` | `[kernel] openat` | A scope filter inside a rule's `filters:` is also pushed to the kernel (for comm/uid/pid/mntns/pidns). |
| `kernel-pathname.yaml` | `[kernel] security_file_open` | `pathname` is the one data field the kernel can filter (longest-prefix maps). |
| `userspace-retval.yaml` | `[user-space] close` | Return-value and non-pathname data filters run in user space. |
| `bootstrap-always-collected.yaml` | `[user-space] sched_process_exec` | Tracee always collects `sched_process_exec/fork/exit`, so scoping them helps only in user space. |
| `union-defeat/` (two policies) | `[user-space] openat` | One broad (unfiltered) selector forces submission for every selector of the same event. |

## The rule of thumb

What filters in the kernel:

- **scope filters** - `comm`, `uid`, `pid` (host), `mntns`, `pidns` (and `uts`, `container`, `tree`,
  `executable` at policy level) - whether written in policy `spec.scope` OR in a rule's `filters:`, and
- a **`pathname`** data filter.

Everything else - non-pathname data filters and return-value filters - is applied in user space. And
because Tracee runs one shared event stream, filters on the same event across all policies compose as a
**union**: a single broad selector (or more than 64 rules on one event) forces the kernel to submit every
instance.

By default the policies are analyzed on their own. Pass your Tracee config with `--config` to fold in
the configured detectors' declared base-event scope filters and reflect the DNS cache (which
force-collects `net_packet_dns`). Process-store and capture settings add only internal control-plane
events (a separate perf buffer), so they do not change the report.

```console
tracee list filterable ./my-policies/ --config /etc/tracee/tracee.yaml
```

See also `tracee list deps <event>` for an event's dependency graph, and
`docs/docs/policies/rules.md` for the full model.
