# YAML Detectors

YAML detectors provide a declarative way to define threat detection and derived events without writing Go code. They offer the same capabilities as Go detectors but with a simpler, configuration-based approach.

## Overview

YAML detectors enable you to:

- **Detect threats** by filtering events and generating alerts
- **Derive events** by enriching or transforming existing events
- **Extract runtime data** from events using JSONPath-like syntax
- **Auto-populate fields** like threat metadata and process ancestry
- **Reuse policy syntax** for event filtering

## Quick Start

Here's a simple YAML detector that identifies execution of networking tools:

```yaml
id: yaml-001
produced_event:
  name: suspicious_binary_execution
  version: 1.0.0
  description: Detects execution of networking tools
  tags:
    - execution
    - defense-evasion
  fields:
    - name: binary_path
      type: string

requirements:
  min_tracee_version: 0.0.0
  events:
    - name: sched_process_exec
      dependency: required
      filters:
        - data.pathname=/usr/bin/nc
        - data.pathname=/usr/bin/ncat

threat:
  severity: medium
  description: Execution of networking tool commonly used for reverse shells
  mitre:
    technique: T1059
    tactic: Execution

auto_populate:
  threat: true
  detected_from: true

output:
  fields:
    - name: binary_path
      expression: data.pathname
```

## Schema Reference

### Top-Level Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique detector identifier (e.g., `yaml-001`) |
| `produced_event` | Yes | Definition of the event this detector produces |
| `requirements` | Yes | Events and conditions required for this detector |
| `threat` | No | Threat metadata (for threat detectors) |
| `auto_populate` | Yes | Fields to auto-populate by the engine |
| `output` | No | Runtime data extraction configuration |

### Produced Event

Defines the event schema that this detector will emit:

```yaml
produced_event:
  name: event_name              # Event name (required)
  version: 1.0.0                # Semantic version (required)
  description: "Description"    # Human-readable description (required)
  tags:                         # Event tags (optional)
    - tag1
    - tag2
  fields:                       # Event data fields (optional)
    - name: field_name
      type: string              # string, int32, int64, uint32, uint64, bool, bytes
```

**Supported field types:**
- `string` - Text data
- `int32` - 32-bit signed integer
- `int64` - 64-bit signed integer
- `uint32` - 32-bit unsigned integer
- `uint64` - 64-bit unsigned integer
- `bool` - Boolean value
- `bytes` - Binary data

### Requirements

Specifies what events and conditions are needed:

```yaml
requirements:
  min_tracee_version: 0.0.0     # Minimum Tracee version (required)
  architectures:                # Supported architectures (optional)
    - x86_64
    - arm64
  events:                       # Event dependencies (required, at least one)
    - name: event_name
      dependency: required      # required or optional
      version_constraints:      # Version constraints (optional)
        min: 1.0.0
        max: 2.0.0
      filters:                  # Event filters (optional)
        - data.field=value
        - scope.field=value
  enrichments:                  # Required enrichments (optional)
    - exec-env                  # Execution environment
    - exec-hash                 # Executable hash
```

**Event Filters:**

Filters use the same syntax as Tracee policies:

- **Data filters**: `data.field_name=value`
- **Scope filters**: `scope.field_name=value`
- **Multiple values**: Comma-separated for OR logic
- **Wildcards**: Prefix (`/tmp*`) or suffix (`*shadow`) matching

Examples:
```yaml
filters:
  - data.pathname=/etc/passwd
  - data.pathname=/etc/shadow      # OR with previous pathname
  - scope.container=true
```

### Threat Metadata

For threat detectors, define threat information:

```yaml
threat:
  severity: high                # low, medium, high, critical
  description: "Threat description"
  mitre:
    technique: T1003            # MITRE ATT&CK technique ID
    tactic: Credential Access   # MITRE ATT&CK tactic
```

### Auto-Populate

Specify which fields the engine should automatically populate:

```yaml
auto_populate:
  threat: true                  # Auto-populate threat metadata
  detected_from: true           # Auto-populate detection source
  process_ancestry: false       # Auto-populate process tree (expensive)
```

**Fields:**
- `threat`: Populates threat metadata from detector definition
- `detected_from`: Adds detector ID and source event information
- `process_ancestry`: Includes full process tree (performance impact)

### Output Data Extraction

Extract runtime values from input events to populate output event fields:

```yaml
output:
  fields:
    - name: output_field_name   # Name in output event
      expression: data.input_field  # Expression path in input event
      optional: false           # Whether field is optional (default: false)
```

**Supported expression paths:**

| Path | Description | Example |
|------|-------------|---------|
| `data.FIELD` | Event data field | `data.pathname` |
| `workload.process.executable.path` | Process executable | Full path to binary |
| `workload.process.pid.value` | Process PID | Process ID |
| `workload.process.unique_id.value` | Process entity ID | Unique process identifier |
| `workload.process.host_pid.value` | Host PID | PID in host namespace |
| `workload.process.real_user.id.value` | Real user ID | UID of process owner |
| `workload.process.thread.name` | Thread name | Thread name |
| `workload.process.thread.syscall` | Current syscall | Syscall name |
| `workload.process.thread.tid.value` | Thread ID | TID |
| `workload.container.id` | Container ID | Container identifier |
| `workload.container.name` | Container name | Container name |
| `workload.container.image.name` | Image name | Container image |
| `workload.container.image.id` | Image ID | Image identifier |
| `workload.container.started` | Container started | Boolean |
| `workload.k8s.pod.name` | Pod name | Kubernetes pod name |
| `workload.k8s.pod.uid` | Pod UID | Kubernetes pod UID |
| `workload.k8s.namespace.name` | Namespace | Kubernetes namespace |
| `timestamp` | Event timestamp | Nanoseconds since epoch |
| `name` | Event name | Input event name |

## Detector Composition

One of the most powerful features of YAML detectors is the ability to **compose them in chains**. A YAML detector can consume events produced by another YAML detector, enabling layered detection patterns and reusable building blocks.

### How It Works

The detector engine automatically resolves event dependencies. When a detector requires an event that's not a built-in kernel event, the engine checks if another detector produces that event. If found, it creates a subscription chain automatically.

### Example: Two-Level Chain

**Base Detector** (reusable pattern):
```yaml
id: yaml-suspicious-exec
produced_event:
  name: suspicious_binary_execution
  version: 1.0.0
  fields:
    - name: binary_path
      type: string

requirements:
  events:
    - name: sched_process_exec
      data_filters:
        - pathname=/usr/bin/nc
        - pathname=/usr/bin/ncat
        - pathname=/tmp/malware

output:
  fields:
    - name: binary_path
      expression: data.pathname
```

**Composed Detector** (adds context):
```yaml
id: yaml-container-suspicious-exec
produced_event:
  name: container_suspicious_execution
  version: 1.0.0
  fields:
    - name: binary_path
      type: string
    - name: container_id
      type: string

requirements:
  events:
    - name: suspicious_binary_execution  # ← Consumes base detector
      scope_filters:
        - container=true

threat:
  severity: high
  description: Suspicious binary executed in container

auto_populate:
  threat: true
  detected_from: true

output:
  fields:
    - name: binary_path
      expression: data.binary_path  # From base detector
    - name: container_id
      expression: workload.container.id
```

### Benefits

- **Reusability**: Share base detectors across teams and organizations
- **Maintainability**: Update base detector, all consumers benefit
- **Modularity**: Each layer has a single responsibility
- **Testing**: Test each layer independently
- **Distribution**: Package and distribute detector libraries

### Use Cases

**Threat Intelligence Integration:**
```yaml
# Community-maintained malware list (base)
id: yaml-known-malware
produced_event:
  name: known_malware_execution
requirements:
  events:
    - name: sched_process_exec
      data_filters:
        - pathname=/known/malware/path1
        - pathname=/known/malware/path2
        # ... hundreds more
```

```yaml
# Organization-specific response (composed)
id: yaml-org-malware-alert
produced_event:
  name: malware_alert
requirements:
  events:
    - name: known_malware_execution  # ← Uses community detector
threat:
  severity: critical
```

**Progressive Refinement:**

You can chain multiple levels (base pattern → container context → production scope):

```
Level 1: cryptominer_execution
    ↓
Level 2: cryptominer_in_container
    ↓
Level 3: cryptominer_production_alert
```

### Best Practices

1. **Design for Reuse**: Make base detectors generic and composable
2. **Single Responsibility**: Each detector should have one clear purpose
3. **Avoid Deep Chains**: Keep chains to 2-3 levels for maintainability
4. **Document Dependencies**: Clearly state what events are consumed
5. **Version Carefully**: Breaking changes in base detectors affect all consumers

### Detector Libraries

Organize detectors into reusable libraries:

```
/etc/tracee/detectors/
├── base-patterns/
│   ├── cryptominers.yaml
│   ├── webshells.yaml
│   └── lolbins.yaml
├── context-enrichment/
│   ├── container-context.yaml
│   └── k8s-context.yaml
└── org-policies/
    ├── production-alerts.yaml
    └── compliance-checks.yaml
```

Load multiple directories:
```bash
tracee --detectors yaml-dir=/etc/tracee/detectors/base-patterns \
       --detectors yaml-dir=/etc/tracee/detectors/org-policies
```

## Complete Examples

### Threat Detector

Detect writes to sensitive system files:

```yaml
id: yaml-sensitive-file-write
produced_event:
  name: sensitive_file_modification
  version: 1.0.0
  description: Modification of sensitive system configuration
  tags:
    - persistence
    - privilege-escalation
  fields:
    - name: filepath
      type: string
    - name: process
      type: string

requirements:
  min_tracee_version: 0.0.0
  events:
    - name: security_file_open
      dependency: required
      filters:
        - data.pathname=/etc/passwd
        - data.pathname=/etc/shadow
        - data.pathname=/etc/sudoers

threat:
  severity: high
  description: Attempt to modify sensitive system files
  mitre:
    technique: T1098
    tactic: Persistence

auto_populate:
  threat: true
  detected_from: true

output:
  fields:
    - name: filepath
      expression: data.pathname
    - name: process
      expression: workload.process.executable.path
```

### Derived Event

Enrich container events with additional context:

```yaml
id: yaml-container-exec
produced_event:
  name: container_command_execution
  version: 1.0.0
  description: Command executed in container with enriched context
  tags:
    - container
    - execution
  fields:
    - name: container_id
      type: string
    - name: container_name
      type: string
    - name: image
      type: string
    - name: command
      type: string

requirements:
  min_tracee_version: 0.0.0
  enrichments:
    - exec-env
  events:
    - name: sched_process_exec
      dependency: required
      filters:
        - scope.container=true

auto_populate:
  detected_from: true

output:
  fields:
    - name: container_id
      expression: workload.container.id
    - name: container_name
      expression: workload.container.name
    - name: image
      expression: workload.container.image.name
    - name: command
      expression: data.pathname
```

## Deployment

### Default Search Paths

Tracee automatically loads YAML detectors from:

1. `./detectors/` - Local directory (relative to working directory)
2. `/etc/tracee/detectors/` - System-wide directory

### Custom Paths

Specify custom directories using:

**CLI Flag:**
```bash
tracee --detectors yaml-dir=/custom/path
```

**Config File:**
```yaml
detectors:
  yaml-dir:
    - /custom/path1
    - /custom/path2
```

### File Organization

Organize YAML detectors by category:

```
/etc/tracee/detectors/
├── persistence/
│   ├── cron-modification.yaml
│   └── systemd-service.yaml
├── privilege-escalation/
│   ├── sudo-abuse.yaml
│   └── setuid-execution.yaml
└── execution/
    ├── suspicious-binaries.yaml
    └── shell-spawning.yaml
```

## Validation

YAML detectors are validated at load time:

- **Schema validation**: Ensures all required fields are present
- **Type checking**: Validates field types match schema
- **Filter syntax**: Checks filter expressions are valid
- **Version constraints**: Validates semantic version format
- **Field extraction**: Verifies expression paths are supported

**Error Handling:**

Invalid detectors are logged as warnings and skipped. Tracee continues loading valid detectors.

## Best Practices

### 1. Use Descriptive IDs

```yaml
# Good
id: yaml-ssh-brute-force

# Bad
id: yaml-001
```

### 2. Provide Clear Descriptions

```yaml
produced_event:
  name: ssh_brute_force_attempt
  description: Multiple failed SSH authentication attempts from same source
```

### 3. Use Specific Filters

```yaml
# Good - specific paths
filters:
  - data.pathname=/etc/passwd
  - data.pathname=/etc/shadow

# Bad - too broad
filters:
  - data.pathname=/etc*
```

### 4. Tag Appropriately

Use consistent tags for categorization:

```yaml
tags:
  - credential-access    # MITRE tactic
  - brute-force         # Technique
  - ssh                 # Technology
```

### 5. Extract Relevant Data

Only extract fields that provide investigative value:

```yaml
output:
  fields:
    - name: source_ip      # Useful for investigation
      expression: data.src_ip
    - name: target_user    # Useful for investigation
      expression: data.username
```

### 6. Set Appropriate Severity

Match severity to actual threat level:

- `low`: Informational, may be benign
- `medium`: Suspicious, requires investigation
- `high`: Likely malicious, immediate attention
- `critical`: Active attack, urgent response

### 7. Version Your Detectors

Use semantic versioning for detector evolution:

```yaml
produced_event:
  version: 1.0.0    # Initial release
  version: 1.1.0    # Added new field
  version: 2.0.0    # Breaking change
```

## Limitations

Current limitations of YAML detectors:

- **No state management**: Cannot track state across events (use Go detectors)
- **No complex logic**: Cannot implement conditional branching or loops
- **No data stores**: Cannot query system state (process tree, DNS cache, etc.)
- **No custom types**: Limited to basic protobuf types
- **No hot reload**: Requires Tracee restart to load new/updated detectors

For advanced use cases requiring these features, use [Go detectors](developer-guide.md).

## Troubleshooting

### Detector Not Loading

Check Tracee logs for validation errors:

```bash
tracee --log debug
```

Common issues:
- Invalid YAML syntax
- Missing required fields
- Invalid filter expressions
- Unsupported field types

### No Events Generated

Verify:
1. Input event is being generated: `tracee --events event_name`
2. Filters are correct: Test with broader filters
3. Event is selected in policy: Check policy configuration

### Incorrect Data Extraction

- Verify expression path exists in input event
- Check field type matches extracted data
- Use `optional: true` for fields that may not exist

## See Also

- [Developer Guide](developer-guide.md) - Writing Go detectors
- [Policy Guide](../policies/index.md) - Event filtering syntax
- [Events Reference](../events/index.md) - Available events
- [Example Detectors](https://github.com/aquasecurity/tracee/tree/main/detectors/yaml) - YAML detector examples

