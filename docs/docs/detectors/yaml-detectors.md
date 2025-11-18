# YAML Detectors

YAML detectors provide a declarative way to define threat detection and derived events without writing Go code. They offer the same capabilities as Go detectors but with a simpler, configuration-based approach.

## Overview

YAML detectors enable you to:

- **Detect threats** by filtering events and generating alerts
- **Derive events** by enriching or transforming existing events
- **Extract runtime data** using CEL expressions or simple field names
- **Write dynamic conditions** using Common Expression Language (CEL)
- **Auto-populate fields** like threat metadata and process ancestry
- **Reuse policy syntax** for static event filtering
- **Chain detectors** to build complex multi-level detection logic

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
    - name: binary_name
      type: string

requirements:
  min_tracee_version: 0.0.0
  events:
    - name: sched_process_exec
      dependency: required
      data_filters:
        - pathname=/usr/bin/nc
        - pathname=/usr/bin/ncat

threat:
  severity: medium
  description: Execution of networking tool commonly used for reverse shells
  mitre:
    technique:
      id: T1059
      name: Command and Scripting Interpreter
    tactic:
      name: Execution

auto_populate:
  threat: true
  detected_from: true

# Simple field extraction using CEL
output:
  fields:
    - name: pathname
      expression: getData("pathname")
    - name: binary_name
      expression: getData("comm")
```

### Simplified CEL Syntax

#### 1. Data Field Access

The `getData()` function extracts event data fields:

```yaml
output:
  fields:
    - name: binary_path
      expression: getData("pathname")
    - name: user_id
      expression: getData("uid")
    - name: process_id
      expression: getData("pid")
```

**Works with any type:**
```yaml
conditions:
  - getData("pathname").startsWith("/tmp")    # String operations
  - getData("pid") > 1000                     # Numeric comparisons
  - getData("uid") == 0                       # Any type supported
```

#### 2. Top-Level Variables

Access workload and timestamp directly:

```yaml
conditions:
  - workload.container.id != ""
  - workload.process.pid > 1000

output:
  fields:
    - name: container_id
      expression: workload.container.id
    - name: pod_name
      expression: workload.kubernetes.pod_name
```

**Available variables:**
- `workload` - Process, container, and Kubernetes context
- `timestamp` - Event timestamp

**Example:**
```yaml
conditions:
  - hasData("pathname")
  - getData("pathname").startsWith("/tmp")
  - getData("uid") == 0
  - workload.container.id != ""

output:
  fields:
    - name: binary
      expression: getData("pathname")
    - name: uid
      expression: getData("uid")
    - name: container
      expression: workload.container.id
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
  min_tracee_version: 0.0.0     # Minimum Tracee version (optional)
  architectures:                # Supported architectures (optional)
    - x86_64
    - arm64
  events:                       # Event dependencies (required, at least one)
    - name: event_name
      dependency: required      # required or optional
      min_version: 1.0.0        # Minimum event version (optional)
      max_version: 2.0.0        # Maximum event version (optional)
      data_filters:             # Data filters (optional)
        - pathname=/etc/passwd
        - uid=0
      scope_filters:            # Scope filters (optional)
        - container=true
  enrichments:                  # Required enrichments (optional)
    - name: exec-env            # Enrichment name
      dependency: required      # required or optional
    - name: exec-hash
      config: digest-inode      # Enrichment-specific config
```

**Event Filters:**

Filters use the same syntax as Tracee policies:

- **Data filters**: Filter by event data fields (e.g., `pathname=/etc/shadow`)
- **Scope filters**: Filter by event scope (e.g., `container=true`)
- **Multiple values**: Comma-separated for OR logic
- **Wildcards**: Prefix (`/tmp*`) or suffix (`*shadow`) matching

Examples:
```yaml
data_filters:
  - pathname=/etc/passwd
  - pathname=/etc/shadow      # OR with previous pathname
scope_filters:
  - container=true
```

### Threat Metadata

For threat detectors, define threat information:

```yaml
threat:
  severity: high                # low, medium, high, critical
  description: "Threat description"
  mitre:
    technique:
      id: T1003               # MITRE ATT&CK technique ID
      name: OS Credential Dumping
    tactic:
      name: Credential Access # MITRE ATT&CK tactic
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

### Conditions (CEL Expressions)

YAML detectors support dynamic runtime conditions using Common Expression Language (CEL). Conditions are evaluated after static filters and all must be true for a detection to fire.

```yaml
conditions:
  - hasData("pathname")  # Check if field exists
  - getData("pathname").startsWith("/tmp")  # String operations
  - getData("uid") > 1000  # Numeric comparisons
  - workload.container.id != ""  # Check container context
```

**CEL Capabilities:**

- **Boolean logic**: `&&`, `||`, `!`, ternary `? :`
- **Comparisons**: `==`, `!=`, `<`, `<=`, `>`, `>=`
- **String methods**: `.startsWith()`, `.endsWith()`, `.contains()`, `.matches()` (regex)
- **List operations**: `in`, `.size()`, `.exists()`, `.all()`
- **Type conversions**: Automatic for compatible types

**Helper Functions:**

| Function | Description | Example |
|----------|-------------|---------|
| `getData("field")` | Extract data field | `getData("pathname")`, `getData("pid")` |
| `hasData("field")` | Check if data field exists | `hasData("pathname")` |

**String Utility Functions:**

| Function | Description | Example |
|----------|-------------|---------|
| `split(str, delimiter)` | Split string into list | `split("a,b,c", ",")` → `["a", "b", "c"]` |
| `join(list, delimiter)` | Join list into string | `join(["a", "b"], ",")` → `"a,b"` |
| `trim(str)` | Remove leading/trailing whitespace | `trim("  hello  ")` → `"hello"` |
| `replace(str, old, new)` | Replace all occurrences | `replace("foo bar", "bar", "baz")` → `"foo baz"` |
| `upper(str)` | Convert to uppercase | `upper("hello")` → `"HELLO"` |
| `lower(str)` | Convert to lowercase | `lower("HELLO")` → `"hello"` |
| `basename(path)` | Get filename from path | `basename("/path/to/file.txt")` → `"file.txt"` |
| `dirname(path)` | Get directory from path | `dirname("/path/to/file.txt")` → `"/path/to"` |

**Performance:**
- Conditions are evaluated with 5ms timeout by default
- Failed evaluations are logged and treated as `false`
- CEL programs are compiled once at load time

### Output Data Extraction

Extract runtime values from input events to populate output event fields using CEL expressions.

```yaml
output:
  fields:
    - name: output_field_name     # Name in output event
      expression: getData("pathname")  # CEL expression (simplified syntax!)
      optional: false              # Whether field is optional (default: false)
```

**CEL Expression Examples:**

| Use Case | Expression |
|----------|------------|
| Extract data field | `getData("pathname")` |
| Extract workload field | `workload.container.id` |
| Conditional extraction | `workload.container.id != "" ? workload.container.id : "unknown"` |
| Extract filename | `basename(getData("pathname"))` |
| Extract directory | `dirname(getData("pathname"))` |
| Split path components | `split(getData("pathname"), "/")` |
| Join path components | `join(["usr", "bin", "nc"], "/")` |
| Normalize case | `lower(getData("comm"))` |
| Replace substring | `replace(getData("pathname"), "/tmp", "/var/tmp")` |
| Combine fields | `getData("comm") + ":" + string(getData("pid"))` |

**Field Semantics:**
- **name**: Required, the output field name
- **expression**: Required, CEL expression to compute the value
- **optional**: If `true`, missing/failed fields are skipped without error

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
      expression: getData("pathname")
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
      expression: getData("binary_path")  # From base detector
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

## Shared Lists

Shared lists allow you to define reusable lists of values (e.g., shell binaries, sensitive paths) that multiple detectors can reference. This avoids duplication and makes maintenance easier.

### List Definition Format

Lists are defined in YAML files placed in a `lists/` subdirectory within your detector directory.

Each list file defines a named list:

```yaml
name: SHELL_BINARIES
type: string_list
values:
  - /bin/sh
  - /bin/bash
  - /bin/dash
  - /bin/zsh
  - /usr/bin/sh
  - /usr/bin/bash
```

**Naming convention:** List names must be uppercase snake_case (e.g., `SHELL_BINARIES`, `SENSITIVE_PATHS`).

**Type:** Currently, only `string_list` is supported.

### Using Lists in Detectors

Reference list variables in CEL conditions using the `in` operator:

```yaml
id: yaml-shell-exec
produced_event:
  name: shell_execution_detected
  version: 1.0.0
  description: Detects execution of shell binaries
  tags:
    - execution
  fields:
    - name: shell_path
      type: string

requirements:
  events:
    - name: sched_process_exec

conditions:
  - getData("pathname") in SHELL_BINARIES  # Uses shared list

output:
  fields:
    - name: shell_path
      expression: getData("pathname")
```

### Complex List Expressions

Lists work with standard CEL operators:

```yaml
conditions:
  # Check membership in multiple lists
  - getData("pathname") in SHELL_BINARIES || getData("pathname") in SCRIPT_INTERPRETERS

  # Combine with other conditions
  - getData("pathname") in SENSITIVE_PATHS && workload.container.id != ""

  # Negate membership
  - !(getData("pathname") in ALLOWED_BINARIES)
```

### List Loading Behavior

- Lists are loaded once at startup from `{detector-dir}/lists/` subdirectory
- Lists are shared across all detectors in the same directory
- Lists are optional - detectors without lists work as before
- Invalid list files prevent all detectors in that directory from loading
- Duplicate list names are not allowed

### Benefits

1. **No duplication**: Define common lists once, use in multiple detectors
2. **Easy maintenance**: Update lists in one place
3. **Zero runtime overhead**: Lists are compiled into the CEL environment at load time
4. **Type safety**: Undefined list references are caught at compile time

## Datastore Functions

YAML detectors can query system state using datastore functions in CEL conditions and output expressions. This enables detectors to make decisions based on process ancestry, container metadata, system information, and more.

### Process Functions

Query process information from Tracee's process datastore.

**`process.get(entityId)`** - Get process information by entity ID

```yaml
conditions:
  # Check if process executable is bash
  - process.get(workload.process.unique_id).exe == "/bin/bash"
  
  # Check process UID
  - process.get(workload.process.unique_id).uid == 0
```

Returns a process object with fields:
- `entity_id` (uint64) - Unique entity ID
- `pid` (uint32) - Process ID
- `ppid` (uint32) - Parent process ID
- `name` (string) - Process name
- `exe` (string) - Executable path
- `start_time` (int64) - Process start timestamp
- `uid` (uint32) - User ID
- `gid` (uint32) - Group ID

Returns `null` if process not found.

**`process.getAncestry(entityId, maxDepth)`** - Get process ancestry chain

```yaml
conditions:
  # Check if any ancestor is a shell
  - process.getAncestry(workload.process.unique_id, 5).exists(p, p.name in SHELL_BINARIES)
  
  # Check if parent process is systemd
  - process.getAncestry(workload.process.unique_id, 2)[1].name == "systemd"
  
  # Verify process depth (count of ancestors)
  - process.getAncestry(workload.process.unique_id, 10).size() < 3
```

Returns a list of process objects, where `[0]` is the process itself, `[1]` is its parent, etc.

**`process.getChildren(entityId)`** - Get child processes

```yaml
conditions:
  # Check if process has spawned children
  - process.getChildren(workload.process.unique_id).size() > 0
  
  # Check if any child is a specific binary
  - process.getChildren(workload.process.unique_id).exists(c, c.exe == "/usr/bin/nc")
```

Returns a list of child process objects.

### Container Functions

Query container information from Tracee's container datastore.

**`container.get(id)`** - Get container by ID

```yaml
conditions:
  # Check container image
  - container.get(workload.container.id).image.startsWith("malicious")
  
  # Check container runtime
  - container.get(workload.container.id).runtime == "docker"
  
  # Check if container has pod metadata
  - container.get(workload.container.id).pod != null
```

Returns a container object with fields:
- `id` (string) - Container ID
- `name` (string) - Container name
- `image` (string) - Container image
- `image_digest` (string) - Image digest (SHA256)
- `runtime` (string) - Container runtime (docker, containerd, cri-o)
- `start_time` (int64) - Container start timestamp
- `pod` (object or null) - Kubernetes pod metadata (if available)
  - `name` (string) - Pod name
  - `uid` (string) - Pod UID
  - `namespace` (string) - Pod namespace
  - `sandbox` (bool) - Whether this is a sandbox container

Returns `null` if container not found.

**`container.getByName(name)`** - Get container by name

```yaml
conditions:
  # Find container by name pattern
  - container.getByName("suspicious-app").image.contains("malware")
```

Returns the same container object as `container.get()`, or `null` if not found.

### System Functions

Access immutable system information collected at Tracee startup.

**`system.info()`** - Get system information

```yaml
conditions:
  # Check architecture
  - system.info().architecture == "x86_64"
  
  # Check kernel version
  - system.info().kernel_release.startsWith("5.")
  
  # Check OS
  - system.info().os_name == "Ubuntu" && system.info().os_version.startsWith("22.")
  
  # Check hostname
  - system.info().hostname.contains("prod")
```

Returns a system info object with fields:
- `architecture` (string) - System architecture (x86_64, arm64, etc.)
- `kernel_release` (string) - Kernel version (e.g., "5.15.0-91-generic")
- `hostname` (string) - System hostname
- `boot_time` (int64) - System boot timestamp
- `tracee_start_time` (int64) - Tracee start timestamp
- `os_name` (string) - OS name (e.g., "Ubuntu")
- `os_version` (string) - OS version (e.g., "22.04")
- `os_pretty_name` (string) - Human-readable OS name
- `tracee_version` (string) - Tracee version

Always returns a valid object (never `null`).

### Kernel Symbol Functions

Resolve kernel addresses and symbol names.

**`kernel.resolveSymbol(address)`** - Resolve address to symbol

```yaml
conditions:
  # Check if address resolves to a known function
  - kernel.resolveSymbol(getData("addr")).exists(s, s.name == "sys_execve")
```

Returns a list of symbol objects (multiple if aliases exist):
- `name` (string) - Symbol name
- `address` (uint64) - Symbol address
- `module` (string) - Module name (e.g., "vmlinux")

Returns empty list if address cannot be resolved.

**`kernel.getSymbolAddress(name)`** - Get symbol address

```yaml
conditions:
  # Check if hooked address differs from expected
  - getData("hooked_addr") != kernel.getSymbolAddress("sys_execve")
  
  # Verify symbol exists
  - kernel.getSymbolAddress("sys_read") > 0u
```

Returns the symbol address as `uint64`, or `0` if not found.

### DNS Functions

Query cached DNS responses.

**`dns.getResponse(query)`** - Get cached DNS response

```yaml
conditions:
  # Check if domain resolves to suspicious IP
  - dns.getResponse(getData("domain")).ips.exists(ip, ip.startsWith("192.168."))
  
  # Check number of resolved IPs
  - dns.getResponse("example.com").ips.size() > 10
```

Returns a DNS response object:
- `query` (string) - Original DNS query
- `ips` (list of strings) - Resolved IP addresses
- `domains` (list of strings) - CNAME chain

Returns `null` if no cached response found.

### Syscall Functions

Map between syscall IDs and names (architecture-specific).

**`syscall.getName(id)`** - Get syscall name from ID

```yaml
conditions:
  # Check if syscall ID is execve
  - syscall.getName(getData("syscall_id")) == "execve"
  
  # Check for specific syscall
  - syscall.getName(59) in ["execve", "execveat"]
```

Returns the syscall name as a string, or empty string `""` if not found.

**`syscall.getId(name)`** - Get syscall ID from name

```yaml
conditions:
  # Check if event is for specific syscalls
  - getData("syscall_id") == syscall.getId("execve") || 
    getData("syscall_id") == syscall.getId("execveat")
```

Returns the syscall ID as `int`, or `-1` if not found.

### Return Values and Error Handling

**Null handling:**
- Functions return `null` when an entity is not found (safe for conditions)
- Non-existent datastores return `null` (graceful degradation)
- Use null-safe checks: `container.get(id) != null` or `container.get(id).image`

**Error propagation:**
- Unexpected errors (not "not found") cause condition evaluation to fail
- The detector will log the error and skip the event

**Performance considerations:**
- Datastore lookups add latency (typically <1ms)
- Use judiciously in high-frequency events
- Prefer static filters (in `requirements`) over dynamic lookups when possible

### Datastore Examples

**Example 1: Detect reverse shell from containerized bash**

```yaml
id: yaml-container-reverse-shell
produced_event:
  name: container_reverse_shell
  version: 1.0.0
  description: Reverse shell spawned from container bash process

requirements:
  events:
    - name: security_socket_connect
      scope_filters:
        - container=true

conditions:
  # Check if process ancestry includes bash
  - process.getAncestry(workload.process.unique_id, 5).exists(p, 
      p.name == "bash" || p.name == "sh")
  
  # Check if container image is not trusted
  - container.get(workload.container.id).image.startsWith("suspicious/")

output:
  fields:
    - name: container_image
      expression: container.get(workload.container.id).image
    - name: shell_exe
      expression: process.getAncestry(workload.process.unique_id, 5).filter(p, 
          p.name in ["bash", "sh"])[0].exe
```

**Example 2: Detect privilege escalation**

```yaml
id: yaml-privilege-escalation
produced_event:
  name: privilege_escalation_detected
  version: 1.0.0
  description: Process escalated privileges from non-root to root

requirements:
  events:
    - name: setuid
      data_filters:
        - uid=0

conditions:
  # Check if parent was non-root
  - process.get(workload.process.unique_id).uid != 0
  
  # Check if not running as expected system process
  - !process.getAncestry(workload.process.unique_id, 3).exists(p, 
      p.name == "systemd" || p.name == "init")
```

**Example 3: Detect kernel rootkit**

```yaml
id: yaml-kernel-rootkit
produced_event:
  name: kernel_rootkit_detected
  version: 1.0.0
  description: Syscall table hooking detected

requirements:
  events:
    - name: hooked_syscalls

conditions:
  # Check if hooked address doesn't match expected symbol
  - getData("hooked_addr") != kernel.getSymbolAddress(getData("syscall_name"))
  
  # Verify it's a critical syscall
  - getData("syscall_name") in ["sys_read", "sys_write", "sys_open", "sys_execve"]
```

## Deployment

### Default Search Path

Tracee automatically loads YAML detectors from `/etc/tracee/detectors/`.

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

### 1. Use Consistent ID Convention

Choose a naming convention and stick to it:

```yaml
# Good - consistent conventions
id: yaml-001           # Simple numeric
id: TRC-YAML-001       # Prefixed with TRC
id: DRV-YAML-001       # Prefixed for derived events

# Bad - inconsistent
id: my-detector-1
id: TRC-002
id: yaml-ssh-detector  # Unnecessarily descriptive (use produced_event.name instead)
```

**Note:** IDs should be unique and stable. Use `produced_event.name` and `description` for descriptive information.

### 2. Provide Clear Descriptions

```yaml
produced_event:
  name: ssh_brute_force_attempt
  description: Multiple failed SSH authentication attempts from same source
```

### 3. Use Specific Filters

```yaml
# Good - specific paths
data_filters:
  - pathname=/etc/passwd
  - pathname=/etc/shadow

# Bad - too broad
data_filters:
  - pathname=/etc*
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
      expression: getData("src_ip")
    - name: target_user    # Useful for investigation
      expression: getData("username")
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

For advanced use cases requiring these features, use [Go detectors](quickstart.md).

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

- [Quick Start Guide](quickstart.md) - First Go detector tutorial
- [API Reference](api-reference.md) - Complete Go detector API
- [DataStore API](datastore-api.md) - Accessing system state from Go detectors
- [Policy Guide](../policies/index.md) - Event filtering syntax
- [Events Reference](../events/index.md) - Available events
- [Example Detectors](https://github.com/aquasecurity/tracee/tree/main/examples/detectors/yaml) - YAML detector examples
