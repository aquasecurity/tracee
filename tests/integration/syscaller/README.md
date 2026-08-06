# syscaller

A tiny, low-noise, self-isolating **syscall-event trigger** for the tracee integration tests.

Some events are hard to produce from a normal program — either the syscall is destructive
(`reboot`, `delete_module`), or the interesting event is *derived* from a syscall that must actually
succeed (`openat` → `security_file_open`). `syscaller` sets its own `comm` (so a policy can scope by
`comm=`) and then issues exactly the syscalls a test asks for, with per-syscall argument strategies.

## Why it works

A tracee syscall-name event fires at `raw_tracepoint/sys_enter`, **on entry, before the syscall
runs and with no success check** (`pkg/ebpf/c/tracee.bpf.c`). So *calling* a syscall triggers its
event even when the call then fails harmlessly on invalid arguments. That is what lets `syscaller`
trigger destructive syscall events safely: it calls them with poison arguments that fail at
validation (`EINVAL`/`EFAULT`/`EBADF`), so the event fires but the destructive effect never lands.

## Why Zig

The tool this replaced was written in Go, and the Go runtime is noisy: just starting it costs ~900
syscalls — a storm of `clone`/`futex`/`mmap`/`rt_sig` from the scheduler and GC — versus about 12 for
a single trigger here. Worse, `PR_SET_NAME` sets the comm per *thread*, so the runtime's extra
threads kept their own comm and leaked into any `comm`-scoped policy.

This tool sidesteps all of that. It targets the raw `std.os.linux` interface — no libc, no threads,
no runtime — so it sits at the syscall-noise floor, and a comm scope sees only the syscalls the test
asked for. As a bonus, one Zig toolchain cross-compiles amd64 and arm64, so the build no longer drags
in the CGO/eBPF environment the Go tool needed (it used to `import pkg/events`).

## CLI

```
syscaller [--unshare] [--cgroup] [--fork-each] <comm> <spec>...
  <spec>       = <n>            issue syscall n with ZERO args (fires the syscall-name event) [legacy]
               = <n>:<strategy> strategy-driven args; strategy = zero | invalid | file        [new]
  --unshare    run in throwaway user/mount/pid/net/uts/ipc/cgroup namespaces (host-safe)
  --fork-each  run EVERY spec in its own fork+watchdog child (contains side effects)
```

`<n>` is the **arch-native syscall number**. The Go test side resolves an event *name* to its number
via the build-tagged `pkg/events/core_{amd64,arm64}.go` tables (`GetDefinitionByName().GetID()`), so
the tool itself does no translation. The bare `<n>` form is unchanged from the old Go tool, so the
existing `event_filters` `useSyscaller` cases (`formatCmdEvents`) keep working with no change.

## Strategies

| strategy  | args                                             | use for |
|-----------|--------------------------------------------------|---------|
| `zero`    | all-zero                                          | any syscall-name event (default) |
| `file`    | `openat`-shaped: `(AT_FDCWD, <scratch file>, O_RDONLY)` | driving *derived* events from a real, successful op (`openat` → `security_file_open`) |
| `invalid` | all-poison (`0xFFFF…`)                            | **destructive** syscalls — fires the event, fails at validation |

The scratch file used by `file` is created **before** the comm change, so its setup syscalls land
under the original comm, not the scoped one, and it is removed on exit.

## Isolation (`--unshare`)

`--unshare` runs the workload inside a throwaway set of namespaces — user, mount, pid, net, uts, ipc
and cgroup — created just for this run. It maps the caller to uid/gid 0 in the new *user* namespace
(with `deny` on setgroups), then forks so the child actually enters the new pid namespace.

The point: that mapped-root has no privilege over the host, so even a syscall whose arguments didn't
fully neuter it can't do damage. A stray mount, kill or network op is confined, and the uts/ipc/
cgroup namespaces also contain `sethostname`/`setdomainname`, IPC and cgroup ops (which matters once
the sweep triggers the whole table). It is defense-in-depth on top of the poison-argument safety —
reach for it whenever you trigger a destructive syscall with `invalid`.

tracee is a single host-wide, scope-filtered collector, so a self-unshared process **is** still
captured. Scope proof tests by `comm` / `mntns` / `pidns` — **not** `container=new`, which keys on a
runtime cgroup + enricher that a bare `unshare` does not have.

## Execution model

By default `zero` and `file` specs run inline while an `invalid` spec runs in a **forked child with a
watchdog**: the child issues the syscall and exits; the parent reaps it and `SIGKILL`s it if it does
not return within a short budget. This makes the tool robust to a syscall that (despite bad args)
blocks or ends the process — including exit-class syscalls, where only the child exits.

`--fork-each` extends the fork+watchdog to **every** spec. That is what lets the coverage sweep
trigger the whole syscall table safely: a syscall with a process-local side effect (`seccomp` strict
mode, `close`, `umask`, `setsid`, `ptrace`→`TRACEME`) is contained to a throwaway child and cannot
poison the specs that follow.

## Safety taxonomy (which strategy per syscall)

Almost every syscall event just needs `zero` (the default): it fires at `sys_enter` before the call
runs, and zero args also defuse most "dangerous" syscalls (a NULL pointer → `EFAULT`, a zero
count/flags → `EINVAL`, a zero fd is just stdin). The **exceptions** live in the Go-side
`syscallerStrategy` / `syscallerSkip` maps (`syscaller_trigger_test.go`), which are the curated,
extensible source of per-syscall knowledge:

- **`invalid`** — destructive syscalls (`reboot`, `kexec_load`/`kexec_file_load`,
  `init_module`/`finit_module`/`delete_module`, `mount`, `pivot_root`, `swapon`/`swapoff`,
  `unlinkat`), plus ones that would end or hang the tool if run inline: exit-class (`exit`,
  `exit_group`), `ptrace` (zero args = `PTRACE_TRACEME`, a real side effect), and `pause` (blocks
  forever — the watchdog kills it).
- **`file`** — `openat` (and x86_64-only `open`), to drive `security_file_open`.
- **skip** — cannot be triggered as a benign, capturable event: `execve`/`execveat` (replace the
  image), `rt_sigreturn` (only valid from a signal frame), and the tool's own fork primitives
  `clone`/`clone3`/`fork`/`vfork`. `runSyscaller` refuses these.

Unlisted syscalls already work via `zero`, so the tool needs no edit when tracee adds syscalls: the
Go side resolves any event name through tracee's own `events.Core` table.

## Staying aligned with tracee

The syscaller does not keep its own syscall list — coverage tracks tracee automatically. Two tests
keep it honest:

- **`Test_SyscallerTableDrift`** (no root): asserts every `syscallerStrategy` key is a real syscall
  event on this arch (so a tracee rename/removal or a typo fails fast), that `syscallerSkip` is a
  consistent deny-list, and that no name is in both. Cheap; runs in the normal suite.
- **`Test_SyscallerSweep`** (root; part of the integration suite): derives the corpus from
  `events.Core` (every syscall event minus the skip set) and triggers the whole table at once under
  `--unshare --fork-each`, asserting each is captured under the tool's comm. When tracee gains
  syscalls (e.g. a PR adding new syscall definitions) this covers them with **no edit here**;
  anything genuinely un-triggerable this way is added to `syscallerSkip` — the failure lists exactly
  what was missed.

### Running the sweep

The sweep is an ordinary integration test, so it runs automatically wherever the suite runs —
including PR CI (`make test-integration` → `go test ./tests/integration/...`). The cost is one extra
short-lived tracee: the whole syscall table is triggered in a single run. Like every integration test
it needs root and eBPF, so it skips on an unprivileged box.

To run just it locally:

```
sudo make test-integration TEST=Test_SyscallerSweep
```

When it fails it lists the syscall events it could not capture; add any that are genuinely
un-triggerable this way to `syscallerSkip`.

## Build

The Makefile builds it as part of the integration flow (it is a prerequisite of
`test-integration`):

```
make dist/syscaller
```

This requires **Zig 0.16** (`scripts/installation/install-zig.sh`, pinned + checksum-verified; the
Makefile's `.checkver_zig` enforces the exact minor). For local development:

```
zig build            # -> zig-out/bin/syscaller
zig build test       # pure arg/strategy unit tests (no root, no syscalls issued)
```

## Using it from Go tests

- Legacy: `formatCmdEvents` (in `event_filters_test.go`) turns a `<comm>` + expected event names into
  `dist/syscaller <comm> <n>...` — unchanged.
- New: `runSyscaller` / `syscallerStrategy` (in `syscaller_trigger_test.go`) emit `<n>:<strategy>` and
  add `--unshare`/`--fork-each`. `Test_SyscallerTrigger` is the end-to-end proof (a destructive batch
  via `--unshare`+`invalid`; `openat` via `file` driving `security_file_open`); `Test_SyscallerSweep`
  is the opt-in full-table coverage sweep; `Test_SyscallerTableDrift` is the no-root table guard.

## Source

- `src/main.zig` — the whole tool.
- `build.zig` — `zig build` / `zig build test` (the Makefile builds `src/main.zig` directly).
