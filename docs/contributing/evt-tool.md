# evt - Event Generator and Stress Testing Tool

`evt` is a testing tool designed to generate events and stress test Tracee's event processing capabilities. It provides two main functionalities: triggering individual events and running comprehensive stress tests.

## Overview

The `evt` tool helps with:

- **Event Generation**: Trigger specific Linux events for testing Tracee's detection capabilities
- **Performance Testing**: Stress test Tracee with high volumes of concurrent events
- **Development**: Validate event detection and measure Tracee's performance under load

## Building

Build the `evt` binary:

```bash
make evt
```

Build the trigger runner container for stress testing:

```bash
make evt-trigger-runner
```

Or with a custom image name:

```bash
EVT_TRIGGER_RUNNER_IMAGE=my-runner:dev make evt-trigger-runner
```

## Commands

### evt trigger

Trigger a specific event type to test Tracee's detection.

**Usage:**

```bash
evt trigger --event <event_name> [flags]
```

**Examples:**

```bash
# Trigger a single event
evt trigger --event security_file_open

# Trigger multiple operations
evt trigger --event ptrace --ops 100

# Parallel execution
evt trigger --event security_file_open --parallel 4 --ops 1000

# Show Tracee bypass flags for an event
evt trigger --event security_file_open --bypass-flags
```

**Flags:**

- `--event, -e <name>`: Event type to trigger (required)
- `--ops, -o <number>`: Number of operations to perform
- `--parallel, -p <number>`: Number of parallel workers (total ops = workers × ops)
- `--sleep, -s <duration>`: Sleep duration between operations
- `--bypass-flags, -b`: Print Tracee bypass flags for the event
- `--wait-signal, -w`: Wait for SIGUSR1 before starting
- `--signal-timeout <duration>`: Timeout for waiting for signal

### evt stress

Run comprehensive stress tests with multiple event types in isolated containers.

Events can be specified via **CLI flags** (`--events` / `-e`) and/or **YAML suite files** (`--events-file`). At least one event must be provided from any source.

**Usage:**

```bash
evt stress [--events <spec> ...] [--events-file <path> ... [--scenario <name> ... | --all-scenarios]] [flags]
```

**Event Specification Format (CLI):**

```
event[:instances=N:ops=N:sleep=dur]
```

- `event`: Event name to trigger
- `instances`: Number of parallel workers
- `ops`: Operations per worker
- `sleep`: Sleep between operations

**Event Suites (YAML):**

You can load events from YAML suite files with `--events-file` / `-E`. A suite defines named **scenarios** (e.g. smoke, filesystem); each scenario lists event specs (same format as CLI) and optional **groups** for organization. Use `--scenario` to run one or more scenarios (repeatable) or `--all-scenarios` to run all. Events from the selected scenario(s) are merged, then any `--events` / `-e` are appended.

- Format: top-level `name`/`description` (optional), required `scenarios` list. Each scenario has `name`, optional `description`, and either `events` (list of specs) or `groups` (each with `name` and `events`).
- Example file: [evt-suite-example.yaml](evt-suite-example.yaml). Full schema and behavior: [evt-events-file-design.md](evt-events-file-design.md).

**Examples:**

```bash
# Basic stress test with CLI events (default settings)
evt stress --events security_file_open --events ptrace

# From a suite file: single scenario (implicit if only one scenario in file)
evt stress --events-file evt-suite-example.yaml

# From a suite file: named scenario
evt stress --events-file evt-suite-example.yaml --scenario smoke

# Multiple scenarios from a suite (repeatable --scenario)
evt stress --events-file evt-suite-example.yaml --scenario smoke --scenario filesystem

# All scenarios from the loaded file(s)
evt stress --events-file evt-suite-example.yaml --all-scenarios

# Merge suite and CLI: scenario events first, then -e
evt stress --events-file evt-suite-example.yaml --scenario smoke -e security_bpf_prog

# Multiple events with custom configurations (CLI only)
evt stress \
  --events security_file_open:instances=10:ops=1000:sleep=1ms \
  --events ptrace:instances=2:ops=100:sleep=100ms

# Performance testing with profiling
evt stress \
  --events security_file_open:instances=16:ops=100000 \
  --pyroscope --pprof --metrics

# Keep Tracee running after test for analysis
evt stress --events ptrace --keep-tracee --pyroscope

# Manual Tracee control
evt stress --events security_file_open --auto-tracee=false

# Custom cooldowns for timing control
evt stress \
  --events security_file_open:instances=10:ops=1000 \
  --tracee-init-cooldown 10s \
  --stress-end-cooldown 30s
```

**Flags:**

**Event Configuration:**
- `--events, -e <spec>`: Event specs to stress test (repeatable). Merge with events from `--events-file` if both are used.
  - Format: `event[:instances=N:ops=N:sleep=dur]`
  - Example: `security_file_open:instances=10:ops=1000:sleep=1ms`
- `--events-file, -E <path>`: Path(s) to YAML suite file(s). May be passed multiple times. Use with `--scenario` or `--all-scenarios` to select which scenarios to run.
- `--scenario <name>`: Scenario(s) to run from the loaded suite file(s). Repeatable (e.g. `--scenario smoke --scenario filesystem`). Mutually exclusive with `--all-scenarios`.
- `--all-scenarios`: Run all scenarios from the loaded suite file(s). Mutually exclusive with `--scenario`.

At least one event must be specified in total (from `--events` and/or from the selected scenario(s) in `--events-file`).

**Container Configuration:**
- `--image <name:tag>`: Trigger runner container image

**Tracee Management:**
- `--auto-tracee`: Automatically manage Tracee lifecycle (start and stop)
- `--keep-tracee`: Keep Tracee running after test (requires `--auto-tracee=true`, useful for profiling analysis)
- `--tracee-binary <path>`: Path to Tracee binary (used when `--auto-tracee=true`)
- `--tracee-output <format:path>`: Tracee output format and path

**Profiling:**
- `--metrics`: Enable Tracee metrics endpoint
- `--pprof`: Enable Tracee pprof profiling endpoint
- `--pyroscope`: Enable Tracee pyroscope continuous profiling

**Execution Control:**
- `--wait-before-trigger`: Wait for user input before triggering events (useful to start profiling/scraping tools)
- `--signal-timeout <duration>`: Timeout for containers waiting for signal
- `--tracee-init-cooldown <duration>`: Cooldown after Tracee starts for stabilization before triggering events
- `--stress-end-cooldown <duration>`: Cooldown after stress completes for stabilization before cleanup
- `--dry-run`: Show what would be executed without running

## Stress Testing Architecture

The stress testing system uses a containerized architecture to run triggers in isolation:

1. **Trigger Runner Container**: Contains the `evt` binary and trigger scripts
2. **Detached Execution**: Containers run in the background with full privileges
3. **Coordinated Start**: All containers wait for SIGUSR1 before triggering events
4. **Automatic Cleanup**: Containers are removed after completion or interruption

### Workflow

1. **Phase 1**: Validate prerequisites (Docker, container image, Tracee binary)
2. **Phase 2**: Start trigger containers (detached mode, waiting for signal)
3. **Phase 3**: Start Tracee with container scope filters (optional)
4. **Phase 4**: Signal containers to start triggering events simultaneously
5. **Phase 5**: Monitor containers until completion
6. **Cleanup**: Stop Tracee (if auto-managed) and remove containers

### Tracee Lifecycle Management

**Auto-managed (default):**
```bash
evt stress --events security_file_open
# Tracee is started and stopped automatically
```

**Keep Tracee running:**
```bash
evt stress --events ptrace --keep-tracee --pyroscope
# Tracee stays running for profiling analysis
# You stop it manually later
```

**Manual control:**
```bash
# Terminal 1: Start Tracee yourself
sudo ./dist/tracee --events security_file_open --server pyroscope

# Terminal 2: Run stress test
evt stress --events security_file_open --auto-tracee=false
```

## Container Image

The `evt-trigger-runner` container image contains:

- `evt` binary for executing triggers
- Trigger scripts for various event types
- Runtime dependencies (bash, strace, bpftrace, etc.)

**Build the image:**

```bash
make evt-trigger-runner
```

**Build with custom name:**

```bash
EVT_TRIGGER_RUNNER_IMAGE=my-runner:test make evt-trigger-runner
```

**Use custom image:**

```bash
evt stress --image my-runner:test --events security_file_open
```

## Available Triggers

The following event triggers are available (located in `cmd/evt/cmd/trigger/triggers/`):

- `security_file_open` - File open operations
- `ptrace` - Process tracing events
- `security_bpf_prog` - BPF program operations
- `security_socket_connect` - Socket connection events
- `security_socket_bind` - Socket bind operations
- `security_socket_create` - Socket creation events
- `sched_process_exec` - Process execution events
- `sched_process_fork` - Process fork events
- `sched_process_exit` - Process exit events
- And many more...

See `cmd/evt/cmd/trigger/triggers/` for the complete list.

## Performance Testing Best Practices

### 1. Disable Output for Maximum Performance

For optimal performance during stress testing, avoid writing event logs:

```bash
# Maximum performance (no logging)
evt stress --events security_file_open:instances=20:ops=10000

# Enable logging if needed
evt stress --events ptrace --tracee-output json:/tmp/events.json
```

### 2. Use Profiling for Analysis

Enable profiling endpoints to analyze Tracee's performance:

```bash
evt stress \
  --events security_file_open:instances=16:ops=100000 \
  --pyroscope --pprof --metrics \
  --keep-tracee
```

Then access:
- Pyroscope UI: http://localhost:4040/?query=tracee.cpu
- Pprof: http://localhost:3366/debug/pprof
- Metrics: http://localhost:3366/metrics

### 3. Control Timing with Cooldowns

Use cooldown periods to ensure accurate measurements:

```bash
# Longer initialization cooldown for complex setups
evt stress \
  --events security_file_open:instances=20:ops=10000 \
  --tracee-init-cooldown 10s

# End cooldown to let Tracee finish processing before cleanup
evt stress \
  --events ptrace:instances=10:ops=5000 \
  --stress-end-cooldown 30s \
  --keep-tracee
```

**When to adjust cooldowns:**
- **Init cooldown**: Provides time for Tracee to stabilize after starting (e.g., loading signatures, initializing eBPF). Increase for complex configurations.
- **End cooldown**: Provides time for system stabilization after stress completes. Increase for complex workloads or when collecting final metrics/profiles.

### 4. Scale Gradually

Start with low load and increase gradually:

```bash
# Low load
evt stress --events security_file_open:instances=1:ops=100

# Medium load
evt stress --events security_file_open:instances=10:ops=1000

# High load
evt stress --events security_file_open:instances=20:ops=10000
```

### 5. Multiple Event Types

Test with multiple event types for realistic scenarios:

```bash
evt stress \
  --events security_file_open:instances=10:ops=5000 \
  --events ptrace:instances=5:ops=1000 \
  --events security_socket_connect:instances=8:ops=2000
```

## Troubleshooting

### Container Image Not Found

```
Error: container image "evt-trigger-runner:latest" not found
```

**Solution:**
```bash
make evt-trigger-runner
```

### Tracee Binary Not Found

```
Error: tracee binary not found at "./dist/tracee"
```

**Solution:**
```bash
make tracee
```

### Docker Not Available

```
Error: docker not available
```

**Solution:** Ensure Docker is installed and running.

### Monitoring Interrupted

When you press Ctrl+C during monitoring:
```
Monitoring interrupted (containers will be cleaned up)
```

This is expected behavior. Containers are automatically cleaned up.

## Integration with Performance Dashboard

The stress testing tool integrates with Tracee's performance dashboard:

```bash
# Start performance dashboard
make -f builder/Makefile.performance dashboard-start

# Run stress test with profiling
evt stress \
  --events security_file_open:instances=16:ops=100000 \
  --pyroscope --metrics \
  --keep-tracee

# Analyze results in dashboard
# Grafana: http://localhost:3000
# Pyroscope: http://localhost:4040

# Stop dashboard when done
make -f builder/Makefile.performance dashboard-stop
```

## See Also

- [evt Events-File Design](evt-events-file-design.md) - YAML suite format, scenarios, and CLI behavior
- [evt Events-File Implementation Plan](evt-events-file-implementation-plan.md) - Implementation and task tracking
- [Performance Considerations](performance.md) - Tracee profiling and benchmarking
- [Testing Coverage](testing-coverage.md) - Tracee testing framework
- [Building](building/building.md) - Building Tracee from source

