# Detector API Reference

Complete reference documentation for the Tracee Detector API. This guide documents all interfaces, structures, and features for writing custom detectors.

**New to detectors?** Start with the [Quick Start Guide](quickstart.md) first.

## Table of Contents

1. [Core Interfaces](#core-interfaces)
2. [DetectorDefinition](#detectordefinition)
3. [Detector Requirements](#detector-requirements)
4. [DetectorOutput](#detectoroutput)
5. [Auto-Population](#auto-population)
6. [Lifecycle Management](#lifecycle-management)
7. [Testing](#testing)
8. [Best Practices](#best-practices)

---

## Core Interfaces

### EventDetector Interface

All detectors must implement this interface:

{% raw %}
```go
type EventDetector interface {
    // GetDefinition returns the detector's metadata and requirements
    // Called once during registration - result is cached
    GetDefinition() DetectorDefinition

    // Init is called once at startup with shared resources
    // Use this to store logger, datastores, and initialize state
    Init(params DetectorParams) error

    // OnEvent processes each matching event
    // Return one or more DetectorOutput, nil for no detection, or error
    OnEvent(ctx context.Context, event *v1beta1.Event) ([]DetectorOutput, error)
}
```
{% endraw %}

### DetectorParams

Provided to `Init()` with shared resources:

{% raw %}
```go
type DetectorParams struct {
    Logger     Logger                 // Structured logger (zap-based)
    DataStores datastores.Registry    // Access to all datastores
    Config     DetectorConfig         // Detector-specific configuration
}
```
{% endraw %}

**Example**:
{% raw %}
```go
func (d *MyDetector) Init(params detection.DetectorParams) error {
    d.logger = params.Logger
    d.dataStores = params.DataStores

    // Check required datastore availability
    if !params.DataStores.IsAvailable("process") {
        return errors.New("process store required but unavailable")
    }

    d.logger.Debugw("Detector initialized", "id", d.GetDefinition().ID)
    return nil
}
```
{% endraw %}

---

## DetectorDefinition

### Complete Structure

{% raw %}
```go
type DetectorDefinition struct {
    // Unique identifier (required)
    ID string

    // Event and datastore requirements (required)
    Requirements DetectorRequirements

    // Output event specification (required)
    ProducedEvent v1beta1.EventDefinition

    // Default threat metadata (optional, recommended for threats)
    ThreatMetadata *v1beta1.Threat

    // Auto-population configuration (optional, recommended)
    AutoPopulate AutoPopulateFields
}
```
{% endraw %}

### Detector ID Conventions

Choose an appropriate ID format:

**Threat Detectors** (TRC-XXX):
{% raw %}
```go
ID: "TRC-001"  // Sensitive file access
ID: "TRC-014"  // Process injection detection
```
{% endraw %}

**Derived Events** (DRV-XXX):
{% raw %}
```go
ID: "DRV-001"  // Container lifecycle events
ID: "DRV-003"  // Hooked syscall detector
```
{% endraw %}

**Custom/Vendor** (VENDOR-XXX):
{% raw %}
```go
ID: "ACME-001"  // Custom company detection
```
{% endraw %}

### ProducedEvent: Event Definition

Defines the event your detector produces:

{% raw %}
```go
ProducedEvent: v1beta1.EventDefinition{
    Name:        "my_detection",           // Required: unique snake_case name
    Description: "Detailed description",    // Required: clear explanation
    Version:     &v1beta1.Version{         // Required: semantic version
        Major: 1,
        Minor: 0,
        Patch: 0,
    },
    Fields: []*v1beta1.EventField{         // Required: output fields schema
        {
            Name: "field_name",
            Type: "const char*",            // Type for display/docs
        },
    },
    Tags: []string{"security", "file"},    // Optional: categorization
}
```
{% endraw %}

**Field Types** (documentation only):

- `const char*` - String
- `int`, `u32`, `u64` - Integers
- `bool` - Boolean
- Custom types for complex data

**Example with all fields**:
{% raw %}
```go
ProducedEvent: v1beta1.EventDefinition{
    Name:        "suspicious_shell_execution",
    Description: "Detects suspicious shell command execution patterns",
    Version:     &v1beta1.Version{Major: 1, Minor: 2, Patch: 0},
    Fields: []*v1beta1.EventField{
        {Name: "command", Type: "const char*"},
        {Name: "shell_type", Type: "const char*"},
        {Name: "risk_score", Type: "int"},
        {Name: "indicators", Type: "const char*[]"},
    },
    Tags: []string{"execution", "defense-evasion"},
}
```
{% endraw %}

### ThreatMetadata: Threat Template

Default threat information, copied to outputs when `AutoPopulate.Threat=true`:

{% raw %}
```go
ThreatMetadata: &v1beta1.Threat{
    Name:        "Short threat name",
    Description: "Detailed threat description",
    Severity:    v1beta1.Severity_MEDIUM,
    Signature: &v1beta1.ThreatSignature{
        ID:   "MITRE T1055",
        Name: "Process Injection",
    },
    Mitre: &v1beta1.MitreAttack{
        Tactic:     []string{"Defense Evasion", "Privilege Escalation"},
        Technique:  []string{"T1055"},
        SubTechnique: []string{"T1055.001"},
    },
}
```
{% endraw %}

**Severity Levels**:

- `Severity_INFO` - Informational events
- `Severity_LOW` - Low-risk threats
- `Severity_MEDIUM` - Moderate threats (default for most detections)
- `Severity_HIGH` - Serious threats requiring immediate attention
- `Severity_CRITICAL` - Critical threats (data exfiltration, rootkits)

**Override per detection**:
{% raw %}
```go
return []detection.DetectorOutput{{
    Data: data,
    Threat: &v1beta1.Threat{
        Name:     "Critical System Compromise",
        Severity: v1beta1.Severity_CRITICAL,  // Override default MEDIUM
    },
}}, nil
```
{% endraw %}

---

## Detector Requirements

### DetectorRequirements Structure

Declare what your detector needs:

{% raw %}
```go
type DetectorRequirements struct {
    // Events lists the events this detector needs to receive
    Events []EventRequirement

    // DataStores lists required datastores with their dependency types
    DataStores []DataStoreRequirement

    // Enrichments lists required event enrichment options
    Enrichments []EnrichmentRequirement

    // Architectures lists supported CPU architectures (empty = all)
    Architectures []string

    // MinTraceeVersion specifies minimum Tracee version (optional, inclusive)
    MinTraceeVersion *v1beta1.Version

    // MaxTraceeVersion specifies maximum Tracee version (optional, exclusive)
    MaxTraceeVersion *v1beta1.Version
}
```
{% endraw %}

### EventRequirement Structure

Declare which events your detector needs:

{% raw %}
```go
type EventRequirement struct {
    Name             string            // Event name (required)
    DataFilters      []string          // Filter by event data (optional)
    ScopeFilters     []string          // Filter by origin (optional)
    MinVersion       *v1beta1.Version  // Minimum event version (optional)
    MaxVersion       *v1beta1.Version  // Maximum event version (optional, exclusive)
    Dependency       DependencyType    // Required vs optional (optional, default Required)
}
```
{% endraw %}

### Basic Requirements

{% raw %}
```go
Requirements: detection.DetectorRequirements{
    Events: []detection.EventRequirement{
        {Name: "security_file_open"},
        {Name: "security_inode_unlink"},
    },
}
```
{% endraw %}

### DataFilters: Filtering Event Data

Engine-level filtering - only matching events reach your detector:

{% raw %}
```go
{
    Name: "security_file_open",
    DataFilters: []string{
        "pathname=/etc/shadow",          // Exact match
        "pathname=/etc/sudoers",          // OR condition
    },
}
```
{% endraw %}

**Filter operators**:
{% raw %}
```go
"field=value"       // Exact match
"field=/path/*"     // Glob pattern (*, ?)
"field!=value"      // Not equal
"field>100"         // Greater than (numeric)
"field<100"         // Less than (numeric)
"field>=100"        // Greater or equal
"field<=100"        // Less or equal
```
{% endraw %}

**Multiple filters** (AND logic):
{% raw %}
```go
DataFilters: []string{
    "pathname=/tmp/*",       // Must match /tmp/*
    "flags>0",               // AND flags > 0
}
```
{% endraw %}

**Common patterns**:
{% raw %}
```go
// Sensitive paths
DataFilters: []string{
    "pathname=/etc/shadow",
    "pathname=/etc/passwd",
    "pathname=/root/.ssh/*",
}

// Specific flags
DataFilters: []string{
    "flags=0x80000",  // O_CLOEXEC
}

// Suspicious syscalls
DataFilters: []string{
    "syscall=ptrace",
    "syscall=process_vm_writev",
}
```
{% endraw %}

### ScopeFilters: Filtering by Origin

Filter by where events originated:

{% raw %}
```go
{
    Name: "security_file_open",
    ScopeFilters: []string{
        "container=started",  // Only containers
    },
}
```
{% endraw %}

**Scope options**:
{% raw %}
```go
"container=started"      // Only from containers
"not-container"          // Only from host (not containers)
"pid=1000"              // Specific PID
"pid!=1"                // Exclude init process
```
{% endraw %}

### Event Version Constraints

Require minimum event version:

{% raw %}
```go
{
    Name: "security_bprm_check",
    MinVersion: &v1beta1.Version{
        Major: 2,
        Minor: 1,
    },
}
```
{% endraw %}

### Required vs Optional Events

{% raw %}
```go
type DependencyType int

const (
    DependencyRequired DependencyType = iota  // Detector fails if event unavailable
    DependencyOptional                         // Detector works without event
)
```
{% endraw %}

**Example**:
{% raw %}
```go
Events: []detection.EventRequirement{
    {
        Name:       "security_file_open",
        Dependency: detection.DependencyRequired,  // Must have
    },
    {
        Name:       "hooked_syscalls",
        Dependency: detection.DependencyOptional,  // Nice to have
    },
}
```
{% endraw %}

### DataStore Requirements

Declare datastore dependencies:

{% raw %}
```go
type DataStoreRequirement struct {
    Name       string          // Datastore name
    Dependency DependencyType  // Required vs optional
}
```
{% endraw %}

**Available datastores**:

- `process` - Process tree and ancestry
- `container` - Container metadata
- `dns` - DNS cache
- `system` - System information
- `syscall` - Syscall mappings
- `symbol` - Kernel symbols

**Example**:
{% raw %}
```go
Requirements: detection.DetectorRequirements{
    Events: []detection.EventRequirement{
        {Name: "security_file_open"},
    },
    DataStores: []detection.DataStoreRequirement{
        {Name: "process", Dependency: detection.DependencyRequired},
        {Name: "container", Dependency: detection.DependencyOptional},
    },
}
```
{% endraw %}

### Enrichment Requirements

Request specific data enrichments on input events:

{% raw %}
```go
type EnrichmentRequirement struct {
    Name       string          // Enrichment option name
    Dependency DependencyType  // Required vs optional
    Config     string          // Enrichment-specific config (optional)
}
```
{% endraw %}

**Available enrichments**:

- `exec-env` - Execution environment variables
- `exec-hash` - Executable file hashes (Config: "inode", "dev-inode", "digest-inode")
- `container` - Container metadata fields in Event struct (Name, Image, Pod info)

**Example**:
{% raw %}
```go
DetectorDefinition{
    ID: "TRC-001",
    Requirements: detection.DetectorRequirements{
        Enrichments: []detection.EnrichmentRequirement{
            {
                Name:       "exec-hash",
                Config:     "digest-inode",
                Dependency: detection.DependencyRequired,
            },
        },
    },
}
```
{% endraw %}

**Container enrichment example**:

{% raw %}
```go
DetectorDefinition{
    ID: "TRC-CONTAINER-001",
    Requirements: detection.DetectorRequirements{
        Events: []detection.EventRequirement{
            {Name: "security_file_open"},
        },
        Enrichments: []detection.EnrichmentRequirement{
            {
                Name:       detection.EnrichmentContainer,
                Dependency: detection.DependencyRequired,
            },
        },
    },
}
```
{% endraw %}

This detector requires container fields to be pre-populated in the Event struct. Without `--enrichment container`, registration will fail.

### Architecture Filtering

Restrict detector to specific CPU architectures (rarely needed):

{% raw %}
```go
DetectorDefinition{
    ID: "TRC-X86-001",
    Requirements: detection.DetectorRequirements{
        Architectures: []string{"amd64"},  // Only x86-64
        // ... rest of requirements
    },
}
```
{% endraw %}

**Supported architectures**:

- `amd64` (x86-64)
- `arm64` (AArch64)

**Default**: Empty slice (or omit field) means the detector supports all architectures.

**When to use**: Only when your detector uses architecture-specific logic or syscalls that don't exist on all platforms.

### Tracee Version Constraints

Require minimum/maximum Tracee version:

{% raw %}
```go
DetectorDefinition{
    ID: "TRC-NEW-001",
    Requirements: detection.DetectorRequirements{
        MinTraceeVersion: &v1beta1.Version{
            Major: 0,
            Minor: 20,
            Patch: 0,
        },
        // MaxTraceeVersion is optional (exclusive)
    },
}
```
{% endraw %}

**When to use**: Your detector relies on features introduced in specific Tracee versions.

### Complete Requirements Example

Putting it all together - a detector with all requirement types:

{% raw %}
```go
DetectorDefinition{
    ID: "TRC-COMPREHENSIVE-001",

    Requirements: detection.DetectorRequirements{
        // Event requirements with filters
        Events: []detection.EventRequirement{
            {
                Name: "security_file_open",
                DataFilters: []string{
                    "pathname=/etc/shadow",
                    "pathname=/etc/sudoers",
                    "pathname=/root/.ssh/*",
                },
                ScopeFilters: []string{
                    "container=started",  // Containers only
                },
                MinVersion:  &v1beta1.Version{Major: 1, Minor: 5},
                Dependency:  detection.DependencyRequired,
            },
            {
                Name:       "security_inode_unlink",
                DataFilters: []string{"pathname=/var/log/*"},
                Dependency:  detection.DependencyOptional,
            },
        },

        // Datastore requirements
        DataStores: []detection.DataStoreRequirement{
            {Name: "process", Dependency: detection.DependencyRequired},
            {Name: "container", Dependency: detection.DependencyOptional},
        },

        // Enrichment requirements
        Enrichments: []detection.EnrichmentRequirement{
            {
                Name:       "exec-hash",
                Config:     "digest-inode",
                Dependency: detection.DependencyRequired,
            },
            {
                Name:       "exec-env",
                Dependency: detection.DependencyOptional,
            },
        },

        // Architecture constraints (rarely needed)
        Architectures: []string{"amd64", "arm64"},

        // Version constraints (if detector uses new features)
        MinTraceeVersion: &v1beta1.Version{
            Major: 0,
            Minor: 20,
            Patch: 0,
        },
        // MaxTraceeVersion is optional (exclusive upper bound)
    },

    // ... rest of definition (ProducedEvent, ThreatMetadata, etc.)
}
```
{% endraw %}

---

## DetectorOutput

### Structure

What your `OnEvent()` returns:

{% raw %}
```go
type DetectorOutput struct {
    // Event data fields (required) - corresponds to ProducedEvent.Fields
    Data []*v1beta1.EventValue

    // Override auto-population settings for this output (optional)
    // If nil, uses Definition.AutoPopulate
    AutoPopulate *AutoPopulateFields

    // Override threat metadata (optional) - overrides Definition.ThreatMetadata
    Threat *v1beta1.Threat

    // Override ancestry depth (optional) - overrides AutoPopulate.ProcessAncestry
    AncestryDepth *uint32
}
```
{% endraw %}

### Creating Event Data

Use helper functions to create type-safe event values:

{% raw %}
```go
// String values
v1beta1.NewStringValue("field_name", "value")

// Integer values
v1beta1.NewInt32Value("count", int32(42))
v1beta1.NewInt64Value("count", int64(42))
v1beta1.NewUInt32Value("flags", uint32(0x1234))
v1beta1.NewUInt64Value("flags", uint64(0x1234))

// Boolean values
v1beta1.NewBoolValue("is_suspicious", true)

// Byte array values
v1beta1.NewBytesValue("data", []byte{0x01, 0x02})

// Complex example
return []detection.DetectorOutput{{
    Data: []*v1beta1.EventValue{
        v1beta1.NewStringValue("command", "/bin/bash -c 'curl evil.com'"),
        v1beta1.NewStringValue("shell", "bash"),
        v1beta1.NewInt32Value("risk_score", int32(85)),
        v1beta1.NewBoolValue("known_ioc", true),
    },
}}, nil
```
{% endraw %}

### Multiple Outputs

Return multiple detections from a single input:

{% raw %}
```go
func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
    var outputs []detection.DetectorOutput

    if condition1 {
        outputs = append(outputs, detection.DetectorOutput{
            Data: []*v1beta1.EventValue{
                v1beta1.NewStringValue("type", "pattern_a"),
            },
        })
    }

    if condition2 {
        outputs = append(outputs, detection.DetectorOutput{
            Data: []*v1beta1.EventValue{
                v1beta1.NewStringValue("type", "pattern_b"),
            },
            Threat: &v1beta1.Threat{
                Severity: v1beta1.Severity_HIGH,  // Different severity
            },
        })
    }

    return outputs, nil
}
```
{% endraw %}

### No Detection

Return `nil, nil` when no detection occurred:

{% raw %}
```go
func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
    value, found := v1beta1.GetData[string](event, "field")
    if !found || !d.isSuspicious(value) {
        return nil, nil  // No detection
    }

    return []detection.DetectorOutput{{...}}, nil
}
```
{% endraw %}

---

## Auto-Population

Declaratively specify automatic field enrichment:

{% raw %}
```go
type AutoPopulateFields struct {
    Threat          bool  // Copy ThreatMetadata to output
    DetectedFrom    bool  // Link to triggering event
    ProcessAncestry bool  // Fetch 5 levels of process ancestry
}
```
{% endraw %}

### Threat: Automatic Threat Metadata

{% raw %}
```go
AutoPopulate: detection.AutoPopulateFields{
    Threat: true,
}
```
{% endraw %}

**Behavior**:

- If `output.Threat` is nil, engine copies `Definition.ThreatMetadata`
- If `output.Threat` is set, that takes precedence
- `Definition.ThreatMetadata` acts as a template/default

**Example**:
{% raw %}
```go
// In definition
ThreatMetadata: &v1beta1.Threat{
    Name:     "Suspicious File Access",
    Severity: v1beta1.Severity_MEDIUM,
}

// In OnEvent - uses default
return []detection.DetectorOutput{{
    Data: data,
    // Threat: nil - engine copies ThreatMetadata above
}}, nil

// In OnEvent - overrides default
return []detection.DetectorOutput{{
    Data: data,
    Threat: &v1beta1.Threat{
        Name:     "Critical System File Access",
        Severity: v1beta1.Severity_CRITICAL,  // Higher severity
    },
}}, nil
```
{% endraw %}

### DetectedFrom: Provenance Tracking

{% raw %}
```go
AutoPopulate: detection.AutoPopulateFields{
    DetectedFrom: true,
}
```
{% endraw %}

**Behavior**: Engine sets `output.DetectedFrom` with:

- `event_id` - Triggering event's ID
- `event_name` - Triggering event's name
- `stack_addresses` - Stack trace (if available)

**Output structure**:
```json
{
  "detected_from": {
    "event_id": 257,
    "event_name": "security_file_open",
    "stack_addresses": [...]
  }
}
```

**Use cases**:
- Debugging: Understand why detector fired
- Forensics: Reconstruct detection chains
- Correlation: Link detections to root causes

#### Detection Chain Preservation

When detectors form chains (detector consuming another detector's output), the engine automatically preserves the complete provenance chain via `DetectedFrom.parent`:

**Example 3-level chain:**

```json
{
  "name": "critical_threat_in_production",
  "detected_from": {
    "id": "7001",
    "name": "suspicious_container_exec",
    "data": [{"name": "binary", "value": "nc"}],
    "parent": {
      "id": "7000",
      "name": "suspicious_binary_exec",
      "data": [{"name": "pathname", "value": "/usr/bin/nc"}],
      "parent": {
        "id": "700",
        "name": "sched_process_exec",
        "data": [{"name": "pathname", "value": "/usr/bin/nc"}]
      }
    }
  }
}
```

**Traversal helpers:**

{% raw %}
```go
// Get full chain (immediate parent to root)
chain := v1beta1.GetDetectionChain(event)

// Get original triggering event
root := v1beta1.GetRootDetection(event)

// Get chain depth
depth := v1beta1.GetChainDepth(event)  // 3 for example above
```
{% endraw %}

This chaining is automatic - detectors don't need to do anything special.

### ProcessAncestry: Automatic Ancestry Enrichment

{% raw %}
```go
AutoPopulate: detection.AutoPopulateFields{
    ProcessAncestry: true,  // Default: 5 levels
}
```
{% endraw %}

**Requirements**:

- Tracee must run with `--stores process`
- Process must be in the process tree
- Default depth: 5 levels (parent → grandparent → great-grandparent → ...)

**Ancestry structure**:
```json
{
  "workload": {
    "process": {
      "entity_id": 12345,
      "pid": 67890,
      "executable": {"path": "/bin/cat"},
      "ancestors": [
        {"entity_id": 12344, "pid": 67889, "executable": {"path": "/bin/bash"}},
        {"entity_id": 12343, "pid": 67888, "thread": {"name": "sshd"}},
        {"entity_id": 1, "pid": 1, "thread": {"name": "systemd"}}
      ]
    }
  }
}
```

**Per-detection ancestry depth control**:
{% raw %}
```go
func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
    severity := d.analyzeThreat(event)

    if severity == "critical" {
        // Deep ancestry for forensics
        depth := uint32(10)
        return []detection.DetectorOutput{{
            Data:          data,
            AncestryDepth: &depth,
        }}, nil
    }

    if severity == "low" {
        // Disable ancestry for performance
        depth := uint32(0)
        return []detection.DetectorOutput{{
            Data:          data,
            AncestryDepth: &depth,
        }}, nil
    }

    // Use default (ProcessAncestry=true → 5 levels)
    return []detection.DetectorOutput{{
        Data: data,
        // AncestryDepth: nil
    }}, nil
}
```
{% endraw %}

### Complete Auto-Population Example

{% raw %}
```go
DetectorDefinition{
    ID: "TRC-001",

    ThreatMetadata: &v1beta1.Threat{
        Name:     "Sensitive File Access",
        Severity: v1beta1.Severity_MEDIUM,
    },

    AutoPopulate: detection.AutoPopulateFields{
        Threat:          true,  // Copy ThreatMetadata
        DetectedFrom:    true,  // Add provenance
        ProcessAncestry: true,  // Add 5-level ancestry
    },
}

// OnEvent just returns data - engine enriches everything else
func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
    return []detection.DetectorOutput{{
        Data: []*v1beta1.EventValue{
            v1beta1.NewStringValue("file", "/etc/shadow"),
        },
        // Engine automatically adds:
        // - Threat (from ThreatMetadata)
        // - DetectedFrom (provenance)
        // - Workload.Process.Ancestors (5 levels)
    }}, nil
}
```
{% endraw %}

### Overriding Auto-Population Per Output

You can override auto-population settings for specific outputs using the `AutoPopulate` field in `DetectorOutput`:

{% raw %}
```go
func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
    severity := d.analyzeThreat(event)

    if severity == "critical" {
        // Enable all enrichment for critical threats
        return []detection.DetectorOutput{{
            Data: data,
            AutoPopulate: &detection.AutoPopulateFields{
                Threat:          true,
                DetectedFrom:    true,
                ProcessAncestry: true,
            },
        }}, nil
    }

    if severity == "low" {
        // Disable enrichment for low-severity detections (performance)
        return []detection.DetectorOutput{{
            Data: data,
            AutoPopulate: &detection.AutoPopulateFields{
                Threat:          true,
                DetectedFrom:    false,  // Skip provenance
                ProcessAncestry: false,  // Skip ancestry
            },
        }}, nil
    }

    // Use default from Definition.AutoPopulate
    return []detection.DetectorOutput{{
        Data: data,
        // AutoPopulate: nil - uses Definition.AutoPopulate
    }}, nil
}
```
{% endraw %}

**Use cases for per-output overrides**:

- Vary enrichment based on threat severity
- Skip expensive enrichment for low-confidence detections
- Add extra context for high-priority alerts

---

## Lifecycle Management

### Init() Best Practices

Called once at startup - use for initialization:

{% raw %}
```go
func (d *MyDetector) Init(params detection.DetectorParams) error {
    // 1. Store logger (always do this)
    d.logger = params.Logger

    // 2. Store datastores if needed
    d.dataStores = params.DataStores

    // 3. Validate required datastores
    if !params.DataStores.IsAvailable("process") {
        return errors.New("process store required but unavailable")
    }

    // 4. Initialize detector state
    d.cache = make(map[string]int)

    // 5. Log initialization
    d.logger.Debugw("Detector initialized",
        "id", d.GetDefinition().ID,
        "version", d.GetDefinition().ProducedEvent.Version,
    )

    return nil
}
```
{% endraw %}

**Don't do in Init()**:

- Heavy computation (blocks startup)
- Network requests
- File I/O (except small config files)

### OnEvent() Guidelines

Called for every matching event - must be fast:

{% raw %}
```go
func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
    // 1. Respect context cancellation
    select {
    case <-ctx.Done():
        return nil, ctx.Err()
    default:
    }

    // 2. Extract required data early
    value, found := v1beta1.GetData[string](event, "field")
    if !found {
        return nil, nil  // Skip silently
    }

    // 3. Fast-path rejection
    if !d.couldBeSuspicious(value) {
        return nil, nil
    }

    // 4. Detailed analysis
    if d.isSuspicious(value) {
        return []detection.DetectorOutput{{
            Data: []*v1beta1.EventValue{
                v1beta1.NewStringValue("field", value),
            },
        }}, nil
    }

    return nil, nil
}
```
{% endraw %}

**Performance tips**:

- Check cheapest conditions first
- Use datastores judiciously (they're fast but not free)
- Avoid allocations in hot path
- Consider caching expensive computations

### Error Handling Guidelines

**Transient errors** - Return error, engine may retry:
{% raw %}
```go
proc, err := d.dataStores.Processes().GetProcess(entityId)
if err != nil && !errors.Is(err, datastores.ErrNotFound) {
    return nil, fmt.Errorf("failed to get process: %w", err)
}
```
{% endraw %}

**Expected conditions** - Return nil detection:
{% raw %}
```go
// Data not found - this is normal
if errors.Is(err, datastores.ErrNotFound) {
    return nil, nil
}

// Optional field missing - expected
value, found := v1beta1.GetData[string](event, "optional_field")
if !found {
    return nil, nil
}
```
{% endraw %}

**Critical errors** - Log and return error:
{% raw %}
```go
if err := d.criticalOperation(); err != nil {
    d.logger.Errorw("Critical operation failed",
        "error", err,
        "event", event.Name,
    )
    return nil, fmt.Errorf("critical failure: %w", err)
}
```
{% endraw %}

**Error wrapping**:
{% raw %}
```go
// Good - provides context
return nil, fmt.Errorf("failed to analyze process %d: %w", pid, err)

// Bad - loses context
return nil, err
```
{% endraw %}

---

## Testing

### Unit Testing Patterns

Test detectors with mock events:

{% raw %}
```go
package detectors

import (
    "context"
    "testing"

    "github.com/aquasecurity/tracee/api/v1beta1"
    "github.com/aquasecurity/tracee/api/v1beta1/detection"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestSensitiveFileAccess_OnEvent(t *testing.T) {
    detector := &SensitiveFileAccess{}

    // Initialize with test params
    err := detector.Init(detection.DetectorParams{
        Logger: &mockLogger{},  // Use your mock logger implementation
        Config: detection.NewEmptyDetectorConfig(),
    })
    require.NoError(t, err)

    t.Run("detects_shadow_access", func(t *testing.T) {
        event := &v1beta1.Event{
            Id:   257,
            Name: "security_file_open",
            Data: []*v1beta1.EventValue{
                v1beta1.NewStringValue("pathname", "/etc/shadow"),
            },
        }

        outputs, err := detector.OnEvent(context.Background(), event)

        require.NoError(t, err)
        require.Len(t, outputs, 1)

        // Verify output data
        data := outputs[0].Data
        require.Len(t, data, 2)
        assert.Equal(t, "file_path", data[0].Name)
        assert.Equal(t, "/etc/shadow", data[0].GetValue().GetStringValue())
    })

    t.Run("ignores_normal_files", func(t *testing.T) {
        event := &v1beta1.Event{
            Id:   257,
            Name: "security_file_open",
            Data: []*v1beta1.EventValue{
                v1beta1.NewStringValue("pathname", "/tmp/normal.txt"),
            },
        }

        outputs, err := detector.OnEvent(context.Background(), event)

        require.NoError(t, err)
        assert.Empty(t, outputs)  // No detection expected
    })
}
```
{% endraw %}

### Mock Logger and DataStores

Create mock implementations for testing:

{% raw %}
```go
// Mock logger for testing
type mockLogger struct{}

func (m *mockLogger) Debugw(msg string, keysAndValues ...any) {}
func (m *mockLogger) Infow(msg string, keysAndValues ...any)  {}
func (m *mockLogger) Warnw(msg string, keysAndValues ...any)  {}
func (m *mockLogger) Errorw(msg string, keysAndValues ...any) {}

// Mock process store
type mockProcessStore struct {
    processes map[uint32]*datastores.ProcessInfo
}

func (m *mockProcessStore) GetProcess(entityId uint32) (*datastores.ProcessInfo, error) {
    proc, ok := m.processes[entityId]
    if !ok {
        return nil, datastores.ErrNotFound
    }
    return proc, nil
}

// Mock datastore registry
type mockRegistry struct {
    processStore datastores.ProcessStore
}

func (m *mockRegistry) Processes() datastores.ProcessStore {
    return m.processStore
}

func (m *mockRegistry) IsAvailable(name string) bool {
    if name == "process" && m.processStore != nil {
        return true
    }
    return false
}

func TestDetectorWithDataStore(t *testing.T) {
    // Create mock store with test data
    mockStore := &mockProcessStore{
        processes: map[uint32]*datastores.ProcessInfo{
            12345: {
                EntityID: 12345,
                Executable: &v1beta1.Executable{Path: "/bin/bash"},
            },
        },
    }

    // Create mock registry
    registry := &mockRegistry{processStore: mockStore}

    // Initialize detector with mocks
    detector := &MyDetector{}
    err := detector.Init(detection.DetectorParams{
        Logger:     &mockLogger{},
        DataStores: registry,
        Config:     detection.NewEmptyDetectorConfig(),
    })
    require.NoError(t, err)

    // Test with mock data
    // ...
}
```
{% endraw %}

### Test Helpers

Use built-in type-safe helpers for data extraction:

{% raw %}
```go
// Type-safe data extraction with assertion
pathname, found := v1beta1.GetData[string](event, "pathname")
require.True(t, found, "pathname field should exist")
assert.Equal(t, "/etc/shadow", pathname)
```
{% endraw %}

---

## Best Practices

### Detector Design Principles

**1. Single Responsibility**
Each detector should focus on one threat pattern or derived event type.

**Good**:
{% raw %}
```go
// Focused on one threat
type ContainerEscapeDetector struct {}

// Focused on one derived event type
type ContainerLifecycleDetector struct {}
```
{% endraw %}

**Bad**:
{% raw %}
```go
// Too broad
type AllContainerThreatsDetector struct {}  // Don't do this!
```
{% endraw %}

**2. Fail Fast**
Reject events as early as possible:

{% raw %}
```go
func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
    // 1. Check required fields first
    pathname, found := v1beta1.GetData[string](event, "pathname")
    if !found {
        return nil, nil
    }

    // 2. Quick pattern checks
    if !strings.HasPrefix(pathname, "/etc/") {
        return nil, nil
    }

    // 3. Expensive checks last
    if d.isKnownMaliciousPattern(pathname) {
        // Create detection
    }

    return nil, nil
}
```
{% endraw %}

**3. Leverage Engine Filtering**
Use `DataFilters` instead of logic in `OnEvent()`:

**Good**:
{% raw %}
```go
DataFilters: []string{
    "pathname=/etc/*",
    "flags>0",
}

func (d *MyDetector) OnEvent(...) {
    // Events already filtered - just detection logic
}
```
{% endraw %}

**Bad**:
{% raw %}
```go
func (d *MyDetector) OnEvent(...) {
    pathname, _ := v1beta1.GetData[string](event, "pathname")
    if !strings.HasPrefix(pathname, "/etc/") {  // Should be in DataFilters!
        return nil, nil
    }
}
```
{% endraw %}

**4. Use Auto-Population**
Let the engine handle enrichment:

**Good**:
{% raw %}
```go
AutoPopulate: detection.AutoPopulateFields{
    Threat:          true,
    DetectedFrom:    true,
    ProcessAncestry: true,
}

func (d *MyDetector) OnEvent(...) {
    return []detection.DetectorOutput{{
        Data: simpleData,  // Just the data fields
    }}, nil
}
```
{% endraw %}

**Bad**:
{% raw %}
```go
func (d *MyDetector) OnEvent(...) {
    // Don't manually query ancestry if you can auto-populate!
    ancestry, _ := d.dataStores.Processes().GetAncestry(entityId, 5)
    // Manual enrichment is error-prone and slower
}
```
{% endraw %}

**5. Graceful Degradation**
Handle missing datastores gracefully:

{% raw %}
```go
// In Init - validate required stores
if !params.DataStores.IsAvailable("process") {
    return errors.New("process store required")
}

// In OnEvent - handle optional stores
if params.DataStores.IsAvailable("container") {
    containerInfo, _ := d.dataStores.Containers().GetContainer(id)
    // Use if available
}
```
{% endraw %}

### Performance Considerations

**1. Minimize DataStore Queries**
{% raw %}
```go
// Good - single query
proc, err := d.dataStores.Processes().GetProcess(entityId)

// Bad - unnecessary queries
proc, _ := d.dataStores.Processes().GetProcess(entityId)
ancestors, _ := d.dataStores.Processes().GetAncestry(entityId, 5)
// Could use AutoPopulate.ProcessAncestry instead!
```
{% endraw %}

**2. Cache Expensive Computations**
{% raw %}
```go
type MyDetector struct {
    mu    sync.RWMutex
    cache map[string]result
}

func (d *MyDetector) expensiveCheck(key string) result {
    // Check cache (read lock)
    d.mu.RLock()
    if cached, ok := d.cache[key]; ok {
        d.mu.RUnlock()
        return cached
    }
    d.mu.RUnlock()

    // Compute (write lock)
    d.mu.Lock()
    defer d.mu.Unlock()

    // Double-check after acquiring write lock
    if cached, ok := d.cache[key]; ok {
        return cached
    }

    result := d.compute(key)
    d.cache[key] = result
    return result
}
```
{% endraw %}

**3. Batch Operations**
If checking multiple conditions, batch them:

{% raw %}
```go
// Good - batch check
if d.isSuspiciousPath(pathname) &&
   d.isSuspiciousFlags(flags) &&
   d.isSuspiciousProcess(proc) {
    // All checks passed
}

// Bad - create intermediary slices
var checks []bool
checks = append(checks, d.isSuspiciousPath(pathname))
checks = append(checks, d.isSuspiciousFlags(flags))
// Unnecessary allocations
```
{% endraw %}

**4. Use Appropriate Data Structures**
{% raw %}
```go
// Good - fast lookup
type MyDetector struct {
    suspiciousPaths map[string]bool  // O(1) lookup
}

// Bad - linear search
type MyDetector struct {
    suspiciousPaths []string  // O(n) lookup
}
```
{% endraw %}

### Code Organization

**File structure**:
```
detectors/
├── my_detector.go           # Detector implementation
├── my_detector_test.go      # Unit tests
└── my_detector_patterns.go  # Optional: complex pattern logic
```

**Detector file template**:
{% raw %}
```go
package detectors

// 1. Imports
import (
    "context"
    "github.com/aquasecurity/tracee/api/v1beta1"
    "github.com/aquasecurity/tracee/api/v1beta1/detection"
)

// 2. Auto-registration
func init() {
    register(&MyDetector{})
}

// 3. Detector struct
type MyDetector struct {
    logger     detection.Logger
    dataStores datastores.Registry
    // ... other state
}

// 4. GetDefinition
func (d *MyDetector) GetDefinition() detection.DetectorDefinition {
    // ...
}

// 5. Init
func (d *MyDetector) Init(params detection.DetectorParams) error {
    // ...
}

// 6. OnEvent
func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
    // ...
}

// 7. Private helper methods
func (d *MyDetector) helperMethod() {
    // ...
}
```
{% endraw %}

---

## Data Access Helpers

### Type-Safe Event Data Extraction

Use generic `GetData[T]` for compile-time type safety:

{% raw %}
```go
// String extraction
pathname, found := v1beta1.GetData[string](event, "pathname")
if !found {
    return nil, nil
}

// Integer extraction
flags, found := v1beta1.GetData[int64](event, "flags")

// Unsigned integer
uid, found := v1beta1.GetData[uint64](event, "uid")

// Boolean
success, found := v1beta1.GetData[bool](event, "success")

// Byte array
data, found := v1beta1.GetData[[]byte](event, "data")
```
{% endraw %}

### Null-Safe Accessors

Use protobuf's generated `Get*()` methods - they're nil-safe:

{% raw %}
```go
// Safe - returns empty string if any field is nil
processPath := event.GetWorkload().GetProcess().GetExecutable().GetPath()

// Safe - returns 0 if nil
entityId := event.GetWorkload().GetProcess().GetEntityId()

// Safe - returns empty slice if nil
ancestors := event.GetWorkload().GetProcess().GetAncestors()
```
{% endraw %}

**Never do this**:
{% raw %}
```go
// UNSAFE - panics if any field is nil!
if event.Workload != nil && event.Workload.Process != nil {
    path := event.Workload.Process.Executable.Path  // Can still panic!
}
```
{% endraw %}

### Common Access Patterns

{% raw %}
```go
// Process information
entityId := event.GetWorkload().GetProcess().GetEntityId()
pid := event.GetWorkload().GetProcess().GetPid()
executable := event.GetWorkload().GetProcess().GetExecutable().GetPath()
commandLine := event.GetWorkload().GetProcess().GetCommandLine()

// Container information (if in container)
containerId := event.GetWorkload().GetContainer().GetId()
containerName := event.GetWorkload().GetContainer().GetName()
containerImage := event.GetWorkload().GetContainer().GetImage().GetName()

// Kubernetes information (if available)
namespace := event.GetWorkload().GetK8s().GetNamespace()
podName := event.GetWorkload().GetK8s().GetPod().GetName()

// User information
uid := event.GetWorkload().GetProcess().GetRealUser().GetId()
username := event.GetWorkload().GetProcess().GetRealUser().GetName()
```
{% endraw %}

---

### Next Steps

- **[Quick Start](quickstart.md)**: Write your first detector
- **[DataStore API](datastore-api.md)**: Complete datastore reference
- **Real Examples**: Browse `detectors/` directory

### Getting Help

- **GitHub Issues**: https://github.com/aquasecurity/tracee/issues
- **Discussions**: https://github.com/aquasecurity/tracee/discussions
- **API Definitions**: `api/v1beta1/detection/detector.go`

---

## Migration from Signatures

This section helps you migrate existing signatures to the new detector API.

### Quick Comparison

| Feature | Old Signature API | New Detector API |
|---------|-------------------|------------------|
| Package | `package main` (plugin) | `package detectors` (compiled-in) |
| Interface | `detect.Signature` | `detection.EventDetector` |
| Event Access | `protocol.Event` (runtime casting) | `*v1beta1.Event` (direct protobuf) |
| Data Extraction | Manual loop through `Args` | `GetData[T]` (type-safe) |
| Event Filtering | `GetSelectedEvents()` (name only) | `EventRequirement` (data + scope filters) |
| Output | Async `ctx.Callback()` | Synchronous return `[]detection.DetectorOutput` |
| Metadata | `GetMetadata()` separate | `GetDefinition()` unified |
| State Management | Manual | LRU caches + datastore access |
| Context Access | Limited | Full datastore access (process, container, etc.) |
| Auto-enrichment | Manual | Declarative (`AutoPopulateFields`) |
| Testing | Callback mocking | Direct function calls |
| Registration | `ExportedSignatures` list | `init()` auto-registration |

### Step-by-Step Migration

**Before** (old signature):

{% raw %}
```go
package main

import (
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
)

type MySignature struct {
	cb detect.SignatureHandler
}

func (s *MySignature) GetMetadata() detect.SignatureMetadata {
	return detect.SignatureMetadata{
		ID:          "TRC-001",
		Name:        "Sensitive File Access",
		Description: "Detects access to sensitive files",
		Version:     "1.0.0",
		Severity:    detect.SeverityMedium,
	}
}

func (s *MySignature) GetSelectedEvents() []detect.SignatureEventSelector {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "security_file_open"},
	}
}

func (s *MySignature) Init(ctx detect.SignatureContext) error {
	s.cb = ctx.Callback
	return nil
}

func (s *MySignature) OnEvent(event protocol.Event) error {
	traceEvent, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("unexpected event type")
	}

	var pathname string
	for _, arg := range traceEvent.Args {
		if arg.Name == "pathname" {
			pathname = arg.Value.(string)
			break
		}
	}

	if !strings.HasPrefix(pathname, "/etc/") {
		return nil
	}

	s.cb(&detect.Finding{
		SigMetadata: s.GetMetadata(),
		Event:       event,
		Data: map[string]interface{}{
			"file": pathname,
		},
	})

	return nil
}

func (s *MySignature) Close() {}
```
{% endraw %}

**After** (new detector):

{% raw %}
```go
package detectors

import (
	"context"
	"strings"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() {
	register(&SensitiveFileAccess{})
}

type SensitiveFileAccess struct {
	logger detection.Logger
}

func (d *SensitiveFileAccess) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-001",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name: "security_file_open",
					DataFilters: []string{"pathname=/etc/*"},  // Engine filters
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "sensitive_file_access",
			Description: "Detects access to sensitive files",
			Version:     &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
			Fields: []*v1beta1.EventField{
				{Name: "file", Type: "const char*"},
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Sensitive File Access",
			Description: "Access to sensitive system files detected",
			Severity:    v1beta1.Severity_MEDIUM,
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:          true,
			DetectedFrom:    true,
			ProcessAncestry: true,
		},
	}
}

func (d *SensitiveFileAccess) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	return nil
}

func (d *SensitiveFileAccess) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Type-safe extraction (no casting)
	pathname, found := v1beta1.GetData[string](event, "pathname")
	if !found {
		return nil, nil
	}

	// No need to filter by /etc/* - engine already did it

	return []detection.DetectorOutput{{
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("file", pathname),
		},
		// Threat, DetectedFrom, ProcessAncestry auto-populated by engine
	}}, nil
}

// Close() is optional - only implement if you need cleanup
```
{% endraw %}

### Migration Checklist

- [ ] Change package from `main` to `detectors`
- [ ] Add `init() { register(&YourDetector{}) }`
- [ ] Update imports to `api/v1beta1` packages
- [ ] Replace `detect.Signature` with `detection.EventDetector`
- [ ] Combine `GetMetadata()` + `GetSelectedEvents()` → `GetDefinition()`
- [ ] Move data filters from `OnEvent()` to `EventRequirement.DataFilters`
- [ ] Replace `protocol.Event` casting with `*v1beta1.Event` parameter
- [ ] Replace manual `Args` loop with `GetData[T]()`
- [ ] Replace `ctx.Callback()` with synchronous `return []detection.DetectorOutput{}`
- [ ] Return `DetectorOutput` with `Data` fields instead of full `v1beta1.Event`
- [ ] Add `AutoPopulateFields` for automatic enrichment
- [ ] Update tests to call `OnEvent()` directly and verify `DetectorOutput`
- [ ] Remove `Close()` if empty (optional interface)

### Common Pattern Translations

**Pattern: Event Selection**
{% raw %}
```go
// Before
GetSelectedEvents() []detect.SignatureEventSelector {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "openat"},
	}
}

// After
Requirements: detection.DetectorRequirements{
	Events: []detection.EventRequirement{
		{Name: "openat"},
	},
},
```
{% endraw %}

**Pattern: Data Extraction**
{% raw %}
```go
// Before
var pathname string
for _, arg := range traceEvent.Args {
	if arg.Name == "pathname" {
		pathname = arg.Value.(string)  // Runtime casting
		break
	}
}

// After
pathname, found := v1beta1.GetData[string](event, "pathname")  // Compile-time safety
if !found {
	return nil, nil
}
```
{% endraw %}

**Pattern: Filtering**
{% raw %}
```go
// Before (in OnEvent)
if !strings.HasPrefix(pathname, "/etc/") {
	return nil  // Manual filter
}

// After (in EventRequirement)
DataFilters: []string{"pathname=/etc/*"},  // Engine filters before dispatch
```
{% endraw %}

**Pattern: Callback → Return**
{% raw %}
```go
// Before
s.cb(&detect.Finding{
	SigMetadata: s.GetMetadata(),
	Event:       event,
	Data:        map[string]interface{}{"file": pathname},
})
return nil

// After
return []detection.DetectorOutput{{
	Data: []*v1beta1.EventValue{
		v1beta1.NewStringValue("file", pathname),
	},
}}, nil
```
{% endraw %}

---

## Troubleshooting

### Problem: Detector Not Running

**Symptoms**: Detector code exists but never triggers

**Diagnosis**:
```bash
# Check if detector is registered
sudo ./dist/tracee list | grep detectors

# Check Tracee logs
sudo ./dist/tracee --logging debug
```

**Solutions**:
1. Verify `init() { register(&YourDetector{}) }` exists
2. Rebuild Tracee: `make clean && make tracee`
3. Check for panics in `Init()` (blocks registration)

### Problem: No Events Received

**Symptoms**: `OnEvent()` never called

**Diagnosis**:
1. Check event name: `sudo ./dist/tracee list | grep event_name`
2. Temporarily remove `DataFilters` to see if they're too restrictive
3. Add debug logging in `OnEvent()`

**Solutions**:
1. Fix event name typo in `EventRequirement.Name`
2. Adjust `DataFilters` - they might be filtering everything out
3. Check `ScopeFilters` - ensure they match your test environment

### Problem: DataStore Returns ErrNotFound

**Symptoms**: `GetProcess()`, `GetContainer()` return `ErrNotFound`

**Possible causes**:
1. Process tree not enabled: `--stores process`
2. Process exited before query
3. Container not tracked yet

**Solutions**:
{% raw %}
```go
// Always handle ErrNotFound gracefully
proc, err := d.dataStores.Processes().GetProcess(entityId)
if errors.Is(err, datastores.ErrNotFound) {
    // This is normal - process might have exited
    return nil, nil
}
if err != nil {
    return nil, fmt.Errorf("unexpected error: %w", err)
}
```
{% endraw %}

### Problem: High CPU Usage

**Symptoms**: Tracee consuming excessive CPU

**Diagnosis**:
1. Check if detector receives too many events
2. Profile detector logic

**Solutions**:
1. Add more restrictive `DataFilters`
2. Optimize detector logic - avoid expensive operations in `OnEvent()`
3. Use caching for repeated computations
4. Consider batching if doing aggregations

### Problem: Memory Leaks

**Symptoms**: Memory usage grows over time

**Causes**:
1. Unbounded maps/slices in detector state
2. Not cleaning up old entries

**Solutions**:
{% raw %}
```go
// Use LRU cache with TTL instead of unbounded maps
import "github.com/hashicorp/golang-lru/v2/expirable"

func (d *MyDetector) Init(params detection.DetectorParams) error {
    // Bounded cache with expiration
    d.cache = expirable.NewLRU[string, *data](
        1000,          // Max entries
        nil,           // No eviction callback
        5*time.Minute, // TTL
    )
    return nil
}
```
{% endraw %}

