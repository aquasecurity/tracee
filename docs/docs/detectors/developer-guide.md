# Detector Developer Guide

Welcome to the Tracee Detector Developer Guide. This comprehensive guide will teach you how to write custom threat detectors and derived event processors using Tracee's modern EventDetector API.

## Table of Contents

1. [Introduction](#introduction)
2. [Quick Start](#quick-start)
3. [Detector Definition](#detector-definition)
4. [Event Requirements](#event-requirements)
5. [Data Access Patterns](#data-access-patterns)
6. [DataStore Usage](#datastore-usage)
7. [Auto-Population](#auto-population)
8. [Advanced Features](#advanced-features)
9. [Lifecycle Management](#lifecycle-management)
10. [Testing](#testing)
11. [Observability](#observability)
12. [Migration from Signatures](#migration-from-signatures)
13. [Best Practices](#best-practices)
14. [Examples](#examples)

---

## Introduction

### What are Detectors?

Detectors are the modern way to write custom threat detection and event derivation logic in Tracee. They replace the older signature system with a more powerful, type-safe, and feature-rich API.

A detector is a Go struct that implements the `EventDetector` interface, analyzing incoming events and producing derived events or threat detections. Detectors can:

- **Detect threats**: Identify malicious behavior (process injection, rootkits, etc.)
- **Derive events**: Transform raw events into higher-level events (container lifecycle, hooked syscalls)
- **Enrich context**: Add process ancestry, container metadata, and system information
- **Filter precisely**: Declaratively filter events by data, scope, and version
- **Access system state**: Query process trees, containers, DNS cache, and more

### When to Write a Detector

Write a detector when you need to:

- Detect specific threat patterns (MITRE ATT&CK techniques)
- Create derived events from raw eBPF events
- Correlate multiple events or system state
- Add custom threat intelligence
- Implement security monitoring rules

### Key Benefits

**Type Safety**: Direct protobuf access with compile-time guarantees (no runtime casting)

**Rich Helpers**: Generic data extraction (`GetData[T]`), null-safe accessors, event creation helpers

**Auto-Population**: Declarative field enrichment (threat metadata, process ancestry, provenance)

**DataStore Access**: Query process trees, containers, DNS cache, kernel symbols, and syscalls

**Declarative Filtering**: Engine-level filtering by event data, scope (host/container), and version

**Better Testing**: Synchronous return values, no callback mocking needed

**Observability**: Built-in Prometheus metrics, structured logging, health monitoring

**No Plugins**: Compiled directly into Tracee (no `.so` files, simpler deployment)

---

## Quick Start

Let's write a simple detector that identifies when sensitive files are accessed.

### Step 1: Create the Detector File

Create `detectors/sensitive_file_access.go`:

```go
package detectors

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

// Auto-register the detector
func init() {
	register(&SensitiveFileAccess{})
}

// SensitiveFileAccess detects access to sensitive system files
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
					DataFilters: []string{
						"pathname=/etc/shadow",
						"pathname=/etc/sudoers",
					},
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "sensitive_file_access",
			Description: "Access to sensitive system files detected",
			Version: &v1beta1.Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
			},
			Fields: []*v1beta1.EventField{
				{Name: "file_path", Type: "const char*"},
				{Name: "process", Type: "const char*"},
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Sensitive File Access",
			Description: "A process attempted to access a sensitive system file",
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
	d.logger.Infow("SensitiveFileAccess detector initialized")
	return nil
}

func (d *SensitiveFileAccess) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Extract file path from event data
	pathname, found := v1beta1.GetData[string](event, "pathname")
	if !found {
		return nil, nil
	}

	// Get process name for enrichment
	processName := ""
	if event.Workload != nil && event.Workload.Process != nil && event.Workload.Process.Executable != nil {
		processName = event.Workload.Process.Executable.Path
	}

	// Return detector output (engine builds final event with auto-populated fields)
	return []detection.DetectorOutput{{
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("file_path", pathname),
			v1beta1.NewStringValue("process", processName),
		},
		// AutoPopulate and Threat from definition are used by engine
	}}, nil
}
```

### Step 2: Build and Test

```bash
# Build Tracee with your detector
make tracee

# Run Tracee with process tree enabled (required for ProcessAncestry)
sudo ./dist/tracee --proctree source=both

# Trigger the detector (in another terminal)
sudo cat /etc/shadow

# View the detection
sudo ./dist/traceectl stream --format json
```

### Step 3: Understand What Happened

1. **Auto-registration**: The `init()` function automatically registered your detector
2. **Engine filtering**: Only `security_file_open` events matching `/etc/shadow` or `/etc/sudoers` reached your detector
3. **Type-safe extraction**: `GetData[string]` extracted the pathname with compile-time type safety
4. **Auto-enrichment**: The engine automatically:
   - Built the complete `v1beta1.Event` from `DetectorOutput`
   - Copied `ThreatMetadata` to `output.Threat`
   - Set `output.DetectedFrom` to reference the input event
   - Queried the process tree and populated 5 levels of ancestry in `output.Workload.Process.Ancestors`
   - Copied `Timestamp`, `Workload`, and `Policies` from input event
5. **Output**: Your detection event was emitted with full context

---

## Detector Definition

The `GetDefinition()` method returns a complete specification of what your detector does and what it needs. This is called once during registration and the result is cached.

### DetectorDefinition Structure

```go
type DetectorDefinition struct {
	ID             string                   // Unique identifier (e.g., "TRC-001", "DRV-002")
	Requirements   DetectorRequirements     // What this detector needs
	ProducedEvent  v1beta1.EventDefinition  // Event schema this detector emits
	ThreatMetadata *v1beta1.Threat          // Threat info (nil for derived events)
	AutoPopulate   AutoPopulateFields       // Declarative field population
}
```

### DetectorOutput Structure

The `OnEvent()` method returns `[]DetectorOutput`, not full `v1beta1.Event` objects. The engine builds the complete events from your outputs.

```go
type DetectorOutput struct {
	Data          []*v1beta1.EventValue  // Your detector's findings (required)
	AutoPopulate  *AutoPopulateFields    // Override definition-level settings (optional)
	Threat        *v1beta1.Threat        // Override definition-level threat (optional)
	AncestryDepth *uint32                // Override ancestry depth (optional)
}
```

**Responsibilities**:
- **Detector**: Provides `Data` fields and optionally overrides `AutoPopulate`/`Threat`
- **Engine**: Builds complete `v1beta1.Event` by:
  - Copying `Timestamp`, `Workload`, and `Policies` from input event
  - Setting `Id` and `Name` from `ProducedEvent` definition
  - Setting `Data` from `DetectorOutput.Data`
  - Auto-populating `Threat`, `DetectedFrom`, and `ProcessAncestry` based on `AutoPopulate` settings

**Example**:
```go
func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Extract and analyze data
	pathname, _ := v1beta1.GetData[string](event, "pathname")

	// Return output - engine builds final event
	return []detection.DetectorOutput{{
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("file_path", pathname),
			v1beta1.NewInt32Value("confidence", 95),
		},
		// Engine will apply AutoPopulate from definition
		// Engine will copy Threat from ThreatMetadata in definition
	}}, nil
}
```

**Per-Detection Overrides**:
```go
// Override threat severity for high-confidence detections
return []detection.DetectorOutput{{
	Data: data,
	Threat: &v1beta1.Threat{
		Name:        "Critical File Access",
		Description: "High-confidence detection of malicious file access",
		Severity:    v1beta1.Severity_CRITICAL,  // Override from MEDIUM
	},
}}, nil

// Request deep ancestry for forensics
return []detection.DetectorOutput{{
	Data: data,
	AncestryDepth: ptr(uint32(10)),  // Request 10 levels instead of default 5
}}, nil

// Disable ancestry for specific detection (performance optimization)
return []detection.DetectorOutput{{
	Data: data,
	AncestryDepth: ptr(uint32(0)),  // Explicitly disable ancestry
}}, nil

// Disable auto-population for specific detection
return []detection.DetectorOutput{{
	Data: data,
	AutoPopulate: &detection.AutoPopulateFields{
		Threat:          true,
		DetectedFrom:    false,  // Don't include provenance for this one
		ProcessAncestry: false,  // Don't query ancestry for this one
	},
}}, nil
```

---

### Detector ID Conventions

Use consistent ID prefixes to indicate detector type:

- **TRC-XXX**: Threat detectors
- **DRV-XXX**: Derived event detectors (built-in event transformations)
- **Custom prefixes**: Use your own prefix for custom detectors

Examples:
```go
ID: "TRC-001"  // Threat detector: sensitive file access
ID: "TRC-102"  // Threat detector: process injection
ID: "DRV-001"  // Derived event: hooked syscall detection
ID: "DRV-002"  // Derived event: container lifecycle tracking
```

### ProducedEvent: Event Definition

Define the event your detector produces:

```go
ProducedEvent: v1beta1.EventDefinition{
	Name:        "process_injection",
	Description: "Process code injection detected via ptrace",
	Version: &v1beta1.Version{
		Major: 1,
		Minor: 0,
		Patch: 0,
	},
	Fields: []*v1beta1.EventField{
		{
			Name: "injection_method",
			Type: "const char*",
			Description: "Method used for injection (ptrace, process_vm_writev, etc)",
		},
		{
			Name: "target_pid",
			Type: "int",
			Description: "PID of the target process",
		},
	},
}
```

**Field Types**: Use C-style types matching Tracee conventions:
- `const char*` for strings
- `int`, `int32`, `uint32`, `uint64` for integers
- `bool` for booleans
- Custom struct names for complex types

### ThreatMetadata: When and How to Use

**Use ThreatMetadata for threat detectors** (actual security threats). Leave it `nil` for derived events (event transformations).

```go
ThreatMetadata: &v1beta1.Threat{
	Name:        "Process Code Injection",
	Description: "Malicious code injection detected via ptrace syscall",
	Severity:    v1beta1.Severity_HIGH,  // LOW, MEDIUM, HIGH, CRITICAL
	Mitre: &v1beta1.Mitre{
		Tactic: &v1beta1.MitreTactic{
			Name: "Defense Evasion",
		},
		Technique: &v1beta1.MitreTechnique{
			Id:   "T1055",
			Name: "Process Injection",
		},
	},
	Properties: map[string]string{  // Optional custom properties
		"data_sources": "ptrace,process_tree",
		"confidence":   "high",
	},
}
```

**Severity Guidelines**:
- **LOW**: Informational, suspicious but not necessarily malicious
- **MEDIUM**: Potentially malicious, requires investigation
- **HIGH**: Likely malicious, immediate attention needed
- **CRITICAL**: Active attack, critical infrastructure at risk

### EventFields: Defining Custom Output Schema

Define the structured data your detector returns in the `Event.Data` field:

```go
Fields: []*v1beta1.EventField{
	{
		Name:        "injection_method",
		Type:        "const char*",
		Description: "Method used for injection",
		Optional:    false,  // This field is always present
	},
	{
		Name:        "target_process",
		Type:        "const char*",
		Description: "Name of the target process",
		Optional:    true,   // This field may be missing
	},
	{
		Name:        "confidence",
		Type:        "int",
		Description: "Detection confidence score (0-100)",
		Optional:    false,
	},
}
```

**When to define fields**:
- ✅ Define fields if you return structured data in `Event.Data`
- ✅ Define fields for derived events (always have custom data)
- ❌ Can omit fields if you only use `Threat` metadata (simple threat detectors)

---

## Event Requirements

The `Requirements` field specifies what events, datastores, and enrichments your detector needs.

### EventRequirement Structure

```go
type EventRequirement struct {
	Name         string                // Event name (e.g., "openat", "execve")
	Dependency   DependencyType        // Required or Optional (default: Required)
	MinVersion   *v1beta1.Version      // Minimum event version (inclusive)
	MaxVersion   *v1beta1.Version      // Maximum event version (exclusive)
	DataFilters  []string              // Filter event data (policy syntax)
	ScopeFilters []string              // Filter event scope (host/container)
}
```

### Required vs Optional Dependencies

**DependencyRequired** (default): Detector registration fails if the event is unavailable.

```go
Events: []detection.EventRequirement{
	{
		Name: "ptrace",
		// Dependency omitted = DependencyRequired (default)
	},
}
```

**DependencyOptional**: Detector registers even if the event is unavailable (graceful degradation).

```go
Events: []detection.EventRequirement{
	{
		Name:       "ptrace",
		Dependency: detection.DependencyRequired,  // Must have this
	},
	{
		Name:       "container_create",
		Dependency: detection.DependencyOptional,  // Nice to have
	},
}
```

**When to use optional**:
- Enrichment events that add context but aren't critical
- Events that may not be available in all environments
- Cross-detector dependencies (detector chains)

### Event Version Constraints

Declare compatibility ranges to prevent silent breakage when event formats change:

```go
Events: []detection.EventRequirement{
	{
		Name:       "openat",
		MinVersion: &v1beta1.Version{Major: 1, Minor: 2},  // >= 1.2.0
		MaxVersion: &v1beta1.Version{Major: 2, Minor: 0},  // < 2.0.0
		// This detector works with openat v1.2.x and v1.x (x >= 2)
	},
}
```

**Version Semantics**:
- `MinVersion`: Inclusive (>=)
- `MaxVersion`: Exclusive (<)
- Both optional (omit for any version)
- Engine validates at registration time

**Example version scenarios**:
```go
// Works with any version
{ Name: "execve" }

// Requires at least v1.2
{ Name: "openat", MinVersion: &v1beta1.Version{Major: 1, Minor: 2} }

// Works up to v2.0 (exclusive)
{ Name: "openat", MaxVersion: &v1beta1.Version{Major: 2, Minor: 0} }

// Works with v1.2.x and v1.x (x >= 2)
{
	Name:       "openat",
	MinVersion: &v1beta1.Version{Major: 1, Minor: 2},
	MaxVersion: &v1beta1.Version{Major: 2, Minor: 0},
}
```

### DataFilters: Filtering Event Data

Filter events by their data fields using Tracee's policy syntax. Only matching events reach your `OnEvent()` method.

**Basic Examples**:
```go
DataFilters: []string{
	"pathname=/etc/shadow",           // Exact match
	"pathname=/etc/*",                 // Wildcard match
	"pathname!=/usr/*",                // Negation
	"uid=0",                           // Numeric match
	"uid!=0",                          // Non-root users
	"flags=O_WRONLY",                  // Flag match
}
```

**Advanced Patterns**:
```go
DataFilters: []string{
	"request=1",                       // ptrace PTRACE_ATTACH
	"pathname=/home/*/.*",             // Hidden files in home dirs
	"pathname=/etc/shadow,/etc/sudoers", // OR condition (comma-separated)
}
```

**Multiple filters are AND**:
```go
DataFilters: []string{
	"pathname=/etc/*",   // AND
	"flags=O_WRONLY",    // AND
	"uid!=0",            // Only non-root writes to /etc/
}
```

**When filters are applied**: Engine filters **before** dispatching to your detector (reduces unnecessary OnEvent() calls).

### ScopeFilters: Filtering by Origin

Filter events by where they originated (host vs containers):

```go
ScopeFilters: []string{
	"container",         // Any container event
	"container=started", // Only events from started containers (not during startup)
	"host",              // Only host events (not from containers)
	"pid!=new",          // Exclude newly created processes
	"container!=new",    // Exclude newly created containers
}
```

**Common patterns**:
```go
// Only monitor host processes
ScopeFilters: []string{"host"}

// Monitor only running containers (reduces initialization noise)
ScopeFilters: []string{"container=started"}
```

### Complete Requirements Example

```go
Requirements: detection.DetectorRequirements{
	Events: []detection.EventRequirement{
		{
			Name:       "ptrace",
			Dependency: detection.DependencyRequired,
			MinVersion: &v1beta1.Version{Major: 1, Minor: 0},
			DataFilters: []string{
				"request=1",  // PTRACE_ATTACH only
			},
			ScopeFilters: []string{
				"container=started",  // Only running containers
			},
		},
		{
			Name:       "container_create",
			Dependency: detection.DependencyOptional,  // For enrichment
		},
	},
	DataStores: []detection.DataStoreRequirement{
		{
			Name:       "process",
			Dependency: detection.DependencyRequired,
		},
		{
			Name:       "container",
			Dependency: detection.DependencyOptional,
		},
	},
	MinTraceeVersion: &v1beta1.Version{Major: 0, Minor: 20, Patch: 0},
},
```

---

## Data Access Patterns

### Accessing Detector Parameters

The `Init()` method receives a `DetectorParams` struct with resources:

```go
type DetectorParams struct {
	Logger     detection.Logger        // Structured logger (scoped to detector ID)
	DataStores datastores.Registry     // Access to system state
	Config     detection.DetectorConfig // Detector configuration (future use)
}
```

**Store references in your detector**:
```go
type MyDetector struct {
	logger     detection.Logger
	dataStores datastores.Registry
	// Your detector state...
}

func (d *MyDetector) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.dataStores = params.DataStores

	// Validate requirements, initialize state
	return nil
}
```

### Type-Safe Event Data Extraction

**Generic GetData[T]** for optional fields (returns zero value if missing):

```go
// Get string field
pathname, found := v1beta1.GetData[string](event, "pathname")
if !found {
	return nil, nil  // Skip if field missing
}

// Get integer field
flags, found := v1beta1.GetData[int32](event, "flags")

// Get other types
uid, found := v1beta1.GetData[uint32](event, "uid")
data, found := v1beta1.GetData[[]byte](event, "data")
enabled, found := v1beta1.GetData[bool](event, "enabled")
```

**GetDataSafe[T]** for required fields (returns error if missing):

```go
pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
if err != nil {
	return nil, fmt.Errorf("missing required field pathname: %w", err)
}

flags, err := v1beta1.GetDataSafe[int32](event, "flags")
if err != nil {
	return nil, fmt.Errorf("missing required field flags: %w", err)
}
```

### Helper Functions for Process/Container Context

**Null-safe accessors** (never panic on missing fields):

```go
// Process information
pid := v1beta1.GetProcessPid(event)           // Returns 0 if missing
processName := v1beta1.GetProcessName(event)  // Returns "" if missing
uid := v1beta1.GetProcessUID(event)           // Returns 0 if missing

// Container information
containerID := v1beta1.GetContainerID(event)  // Returns "" if missing
```

### Creating Output Events

**Return DetectorOutput** with your detection data:

```go
func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Extract data
	pathname, _ := v1beta1.GetData[string](event, "pathname")

	// Return detector output (engine builds complete event)
	return []detection.DetectorOutput{{
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("file_path", "/etc/shadow"),
			v1beta1.NewInt32Value("confidence", 95),
			v1beta1.NewBoolValue("verified", true),
		},
		// Engine applies AutoPopulate from definition
		// Engine copies Threat from ThreatMetadata in definition
	}}, nil
}
```

**Event value constructors**:
```go
v1beta1.NewStringValue(name, value string)
v1beta1.NewInt32Value(name string, value int32)
v1beta1.NewUInt32Value(name string, value uint32)
v1beta1.NewInt64Value(name string, value int64)
v1beta1.NewUInt64Value(name string, value uint64)
v1beta1.NewBoolValue(name string, value bool)
v1beta1.NewBytesValue(name string, value []byte)
```

### Complete Data Access Example

```go
func (d *FileAccessDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Required field - return error if missing
	pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
	if err != nil {
		return nil, fmt.Errorf("missing pathname: %w", err)
	}

	// Optional field - graceful degradation
	flags, found := v1beta1.GetData[int32](event, "flags")
	if !found {
		d.logger.Debugw("flags field missing, using default")
		flags = 0
	}

	// Process context
	pid := v1beta1.GetProcessPid(event)
	processName := v1beta1.GetProcessName(event)

	// Container context (may be empty for host processes)
	containerID := v1beta1.GetContainerID(event)

	// Build detector output data
	data := []*v1beta1.EventValue{
		v1beta1.NewStringValue("file", pathname),
		v1beta1.NewInt32Value("flags", flags),
		v1beta1.NewUInt32Value("pid", pid),
		v1beta1.NewStringValue("process", processName),
	}

	if containerID != "" {
		data = append(data,
			v1beta1.NewStringValue("container_id", containerID))
	}

	// Return output (engine builds final event)
	return []detection.DetectorOutput{{Data: data}}, nil
}
```

---

## DataStore Usage

DataStores provide read-only access to system state. See the [DataStore API Reference](datastore-api.md) for complete documentation.

### Overview of Available Stores

```go
// Available via params.DataStores in Init() and stored in your detector
type Registry interface {
	Processes() ProcessStore         // Process tree and ancestry
	Containers() ContainerStore       // Container metadata
	KernelSymbols() KernelSymbolStore // Kernel symbol resolution
	DNS() DNSStore                    // DNS cache
	System() SystemStore              // System information
	Syscalls() SyscallStore           // Syscall ID/name mapping
}
```

### ProcessStore: Process Information

**Basic usage**:
```go
func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Get entity ID from event (hash, not PID)
	entityId := event.Workload.Process.EntityId.Value

	// Lookup process information
	processStore := d.dataStores.Processes()
	proc, err := processStore.GetProcess(entityId)
	if errors.Is(err, datastores.ErrNotFound) {
		// Process not in tree (may have exited)
		return nil, nil
	}

	// Use process information
	d.logger.Infow("Found process",
		"pid", proc.PID,           // OS PID (for logging)
		"name", proc.Name,         // Binary name: "bash"
		"exe", proc.Exe,           // Full path: "/usr/bin/bash"
		"uid", proc.UID,
		"start_time", proc.StartTime)

	// ... detection logic
}
```

**Get process ancestry** (5 levels by default):
```go
// Retrieve ancestor chain
ancestry, err := d.dataStores.Processes().GetAncestry(entityId, 5)
if err != nil {
	d.logger.Warnw("Failed to get ancestry", "error", err)
	return nil, nil
}

// ancestry[0] = process itself
// ancestry[1] = parent
// ancestry[2] = grandparent, etc.
for i, ancestor := range ancestry {
	d.logger.Debugw("Ancestor",
		"level", i,
		"pid", ancestor.PID,
		"name", ancestor.Name,
		"exe", ancestor.Exe)
}

// Example: Check if parent is suspicious
if len(ancestry) > 1 {
	parent := ancestry[1]
	if strings.Contains(parent.Exe, "malicious") {
		// Trigger detection
	}
}
```

**Get child processes**:
```go
children, err := d.dataStores.Processes().GetChildProcesses(entityId)
if err != nil {
	return nil, err
}

d.logger.Infow("Found children", "count", len(children))
for _, child := range children {
	d.logger.Debugw("Child process",
		"pid", child.PID,
		"name", child.Name)
}
```

**EntityID vs PID**:

!!! Important "Use EntityID, not PID"
    ProcessStore uses **EntityID** (hash) as the primary key, not PID. PIDs can be reused after a process exits, but EntityID is unique for the lifetime of the process.

    - **EntityID**: Unique hash from ProcessTree (matches `event.Workload.Process.EntityId`)
    - **PID**: OS process ID (for display/logging only)

    Always use EntityID for lookups, PID for logging.

### ContainerStore: Container Metadata

**Get container by ID**:
```go
containerID := v1beta1.GetContainerID(event)
if containerID == "" {
	// Not a container event
	return nil, nil
}

containerStore := d.dataStores.Containers()
container, err := containerStore.GetContainer(containerID)
if errors.Is(err, datastores.ErrNotFound) {
	d.logger.Debugw("Container not found", "id", containerID)
	return nil, nil
}

d.logger.Infow("Container info",
	"id", container.ID,
	"name", container.Name,
	"image", container.Image,
	"runtime", container.Runtime,
	"start_time", container.StartTime)

// Kubernetes pod information (if available)
if container.Pod != nil {
	d.logger.Infow("Pod info",
		"name", container.Pod.Name,
		"namespace", container.Pod.Namespace,
		"sandbox", container.Pod.Sandbox)
}
```

**Get container by name**:
```go
container, err := d.dataStores.Containers().GetContainerByName("web-server")
if errors.Is(err, datastores.ErrNotFound) {
	return nil, nil
}
```

### SystemStore: System Information

Get immutable system information (collected at Tracee startup):

```go
systemStore := d.dataStores.System()
if systemStore == nil {
	// System store not available
	return nil, nil
}

sysInfo := systemStore.GetSystemInfo()

d.logger.Infow("System information",
	"arch", sysInfo.Architecture,        // "x86_64", "aarch64"
	"kernel", sysInfo.KernelRelease,     // "5.15.0-generic"
	"os", sysInfo.OSPrettyName,          // "Ubuntu 22.04 LTS"
	"hostname", sysInfo.Hostname,
	"tracee_version", sysInfo.TraceeVersion,
	"boot_time", sysInfo.BootTime,
	"tracee_start", sysInfo.TraceeStartTime)

// Check architecture
if sysInfo.Architecture == "x86_64" {
	// x86-specific logic
}

// Add to detection metadata
detection.Data = append(detection.Data,
	v1beta1.NewStringValue("system_arch", sysInfo.Architecture),
	v1beta1.NewStringValue("kernel_version", sysInfo.KernelRelease))
```

### SyscallStore: Syscall Mapping

**Get syscall name from ID**:
```go
syscallStore := d.dataStores.Syscalls()
name, err := syscallStore.GetSyscallName(59) // sys_execve on x86_64
if err == nil {
	d.logger.Infow("Syscall", "id", 59, "name", name)
}
```

**Get syscall ID from name**:
```go
id, err := d.dataStores.Syscalls().GetSyscallID("execve")
if err == nil {
	d.logger.Infow("Syscall", "name", "execve", "id", id)
}
```

!!! Note "Architecture-Specific"
    Syscall IDs are architecture-specific. ID 59 is `execve` on x86_64 but may be different on ARM.

### Graceful Degradation Patterns

Always check if optional stores are available:

```go
// Pattern 1: Check for nil
systemStore := d.dataStores.System()
if systemStore != nil {
	sysInfo := systemStore.GetSystemInfo()
	// Use system info
}

// Pattern 2: Handle missing data
containerStore := d.dataStores.Containers()
container, err := containerStore.GetContainer(containerID)
if errors.Is(err, datastores.ErrNotFound) {
	d.logger.Debugw("Container not found, proceeding without container context")
	// Continue with detection, just without container enrichment
}

// Pattern 3: Check in Init()
func (d *MyDetector) Init(params detection.DetectorParams) error {
	d.dataStores = params.DataStores

	// Warn if optional store unavailable
	if d.dataStores.System() == nil {
		d.logger.Warnw("System store not available, some features disabled")
	}

	return nil
}
```

### Complete DataStore Example

```go
func (d *ContainerEscapeDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Get process information
	entityId := event.Workload.Process.EntityId.Value
	proc, err := d.dataStores.Processes().GetProcess(entityId)
	if errors.Is(err, datastores.ErrNotFound) {
		return nil, nil
	}

	// Get container information
	containerID := v1beta1.GetContainerID(event)
	if containerID == "" {
		return nil, nil  // Not a container event
	}

	container, err := d.dataStores.Containers().GetContainer(containerID)
	if errors.Is(err, datastores.ErrNotFound) {
		d.logger.Warnw("Container not found", "id", containerID)
		return nil, nil
	}

	// Analyze process ancestry
	ancestry, err := d.dataStores.Processes().GetAncestry(entityId, 5)
	if err != nil {
		return nil, err
	}

	// Detection logic: Check if process escaped container
	if d.detectEscape(proc, container, ancestry) {
		return []detection.DetectorOutput{{
			Data: []*v1beta1.EventValue{
				v1beta1.NewStringValue("container_name", container.Name),
				v1beta1.NewStringValue("container_image", container.Image),
				v1beta1.NewStringValue("process", proc.Exe),
				v1beta1.NewUInt32Value("pid", proc.PID),
			},
		}}, nil
	}

	return nil, nil
}
```

---

## Auto-Population

Auto-population declaratively specifies which output event fields the engine should automatically populate. This eliminates boilerplate and ensures consistency.

### AutoPopulateFields Overview

```go
type AutoPopulateFields struct {
	Threat          bool  // Copy ThreatMetadata to output Event.Threat
	DetectedFrom    bool  // Set DetectedFrom to reference input event
	ProcessAncestry bool  // Query process store and populate 5-level ancestry
}
```

**All fields default to false** (opt-in model). Enable only what you need.

### Threat: Automatic Threat Metadata Copy

**When to use**: All threat detectors (detections of malicious activity)

**What it does**: Engine copies `ThreatMetadata` from your definition to the output event's `Threat` field.

```go
ThreatMetadata: &v1beta1.Threat{
	Name:        "Process Code Injection",
	Description: "Malicious code injection detected",
	Severity:    v1beta1.Severity_HIGH,
	Mitre: &v1beta1.Mitre{
		Tactic:    &v1beta1.MitreTactic{Name: "Defense Evasion"},
		Technique: &v1beta1.MitreTechnique{Id: "T1055", Name: "Process Injection"},
	},
},
AutoPopulate: detection.AutoPopulateFields{
	Threat: true,  // Engine copies ThreatMetadata to output.Threat
},
```

**Your OnEvent() code**:
```go
func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// No need to set Threat - engine does it automatically
	return []detection.DetectorOutput{{
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("suspicious_action", "code_injection"),
		},
		// Threat is automatically copied from ThreatMetadata by engine
	}}, nil
}
```

!!! Important "Threat is Immutable in Definition"
    ThreatMetadata in the definition is **static** (defined once). To customize threat per detection, use `DetectorOutput.Threat` to override.

**Wrong** (don't use definition threat for runtime data):
```go
// Don't try to modify the definition's ThreatMetadata
detection.Threat.Properties["runtime_data"] = value
```

**Right** (use Event.Data or DetectorOutput.Threat):
```go
// Option 1: Add runtime context to Data fields
return []detection.DetectorOutput{{
	Data: []*v1beta1.EventValue{
		v1beta1.NewStringValue("runtime_context", value),
	},
}}, nil

// Option 2: Override threat for this specific detection
return []detection.DetectorOutput{{
	Data: data,
	Threat: &v1beta1.Threat{
		Name:        "High Confidence Attack",
		Description: "Attack confirmed with multiple indicators",
		Severity:    v1beta1.Severity_CRITICAL,  // Override severity
	},
}}, nil
```

### DetectedFrom: Provenance Tracking

**When to use**: All detectors (threat and derived events) that want audit trails

**What it does**: Engine sets `Event.DetectedFrom` to reference the input event that triggered this detection.

```go
AutoPopulate: detection.AutoPopulateFields{
	DetectedFrom: true,  // Engine populates provenance
},
```

**Result**: Output event includes:
```json
{
  "name": "process_injection",
  "detected_from": {
    "id": 12345,
    "name": "ptrace",
    "data": { ... }
  }
}
```

**Benefits**:
- Audit trail: Track which raw event triggered each detection
- Forensics: Reconstruct detection chains
- Debugging: Understand why detector fired

### ProcessAncestry: Automatic Ancestry Enrichment

**When to use**: Detectors that need process lineage context (family relationships)

**What it does**: Engine queries the process store and populates `Event.Workload.Process.Ancestors` with ancestors.

**Default depth**: 5 levels when `ProcessAncestry: true`

```go
AutoPopulate: detection.AutoPopulateFields{
	ProcessAncestry: true,  // Engine queries process store (default: 5 levels)
},
```

**Priority for ancestry depth**:
1. `output.AncestryDepth` (per-detection override) - most specific
2. `definition.ProcessAncestry` (boolean) - default depth of 5
3. `nil` / `false` = disabled (no ancestry fetched)

**Per-detection depth control**:
```go
// Request deep ancestry for critical detections
return []detection.DetectorOutput{{
	Data: data,
	AncestryDepth: ptr(uint32(10)),  // Override to 10 levels
}}, nil

// Disable ancestry for specific detection
return []detection.DetectorOutput{{
	Data: data,
	AncestryDepth: ptr(uint32(0)),  // Override to disabled
}}, nil

// Use definition default (5 levels)
return []detection.DetectorOutput{{
	Data: data,
	// AncestryDepth: nil - uses ProcessAncestry boolean
}}, nil
```

**Requirements**:
1. ProcessStore must be available (required datastore)
2. Event must have a valid process EntityID
3. Tracee must be running with `--proctree source=both` (or `source=events` or `source=signals`)

**Result**: Output event includes:
```json
{
  "name": "process_injection",
  "workload": {
    "process": {
      "entity_id": 123,
      "pid": 5678,
      "ancestors": [
        {"entity_id": 100, "pid": 1234, "executable": {"path": "/usr/bin/bash"}},
        {"entity_id": 50, "pid": 1, "thread": {"name": "systemd"}},
        ...
      ]
    }
  }
}
```

**Ancestry structure**:
- `ancestors[0]` = parent process
- `ancestors[1]` = grandparent process
- `ancestors[2]` = great-grandparent process
- ... up to 5 levels

**Manual override** (rare cases):
```go
// Engine only populates if Ancestors is empty
func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]*v1beta1.Event, error) {
	detection := v1beta1.CreateEventFromBase(event)

	// Custom ancestry logic (engine skips auto-population)
	detection.Workload.Process.Ancestors = customAncestry

	return []*v1beta1.Event{detection}, nil
}
```

### Usage Patterns

**Pattern 1: Full auto-population (threat detector)**

Most common for threat detectors:
```go
AutoPopulate: detection.AutoPopulateFields{
	Threat:          true,  // Copy threat metadata
	DetectedFrom:    true,  // Provenance tracking
	ProcessAncestry: true,  // Process lineage
},
```

Your OnEvent() is minimal:
```go
func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Threat, DetectedFrom, ProcessAncestry all auto-populated by engine
	return []detection.DetectorOutput{{
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("indicator", "malicious_pattern"),
		},
	}}, nil
}
```

**Pattern 2: No auto-population (derived event)**

Default for derived events:
```go
// AutoPopulate omitted = all false
```

Your OnEvent() sets everything manually:
```go
func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	return []detection.DetectorOutput{{
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("derived_info", "value"),
		},
		// No auto-population
	}}, nil
}
```

**Pattern 3: Partial auto-population (derived event with context)**

Derived events that want provenance:
```go
AutoPopulate: detection.AutoPopulateFields{
	DetectedFrom: true,  // Only DetectedFrom
},
```

**Pattern 4: Threat detector with runtime context**

Threat detector that adds runtime-specific data:
```go
AutoPopulate: detection.AutoPopulateFields{
	Threat:          true,
	DetectedFrom:    true,
	ProcessAncestry: true,
},
```

```go
func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Threat auto-populated (static)
	// Add runtime-specific context in Data (dynamic)
	return []detection.DetectorOutput{{
		Data: []*v1beta1.EventValue{
			v1beta1.NewUInt32Value("target_pid", targetPid),
			v1beta1.NewStringValue("injection_method", "ptrace"),
			v1beta1.NewInt32Value("confidence", 95),
		},
	}}, nil
}
```

### Performance Considerations

**ProcessAncestry is expensive** (datastore query). Only enable if you need it:

✅ **Enable when**:
- Detecting process injection/escalation patterns
- Analyzing privilege escalation chains
- Investigating process family behavior
- Need full context for forensics

❌ **Don't enable when**:
- Simple file access detection
- Single-process behavior analysis
- Performance-critical hot paths
- You don't use ancestry data

---

## Advanced Features

### DataStore Requirements Validation

Declare datastores your detector depends on:

```go
Requirements: detection.DetectorRequirements{
	DataStores: []detection.DataStoreRequirement{
		{
			Name:       "process",
			Dependency: detection.DependencyRequired,  // Must have
		},
		{
			Name:       "container",
			Dependency: detection.DependencyOptional,  // Nice to have
		},
		{
			Name:       "symbol",
			Dependency: detection.DependencyRequired,
		},
	},
},
```

**Available datastores**:
- `"process"` - ProcessStore
- `"container"` - ContainerStore
- `"symbol"` - KernelSymbolStore
- `"dns"` - DNSStore
- `"system"` - SystemStore
- `"syscall"` - SyscallStore

**Engine behavior**:
- **Required**: Registration fails if datastore unavailable
- **Optional**: Detector registers, must handle absence gracefully

### Enrichment Requirements

Declare event enrichment options your detector needs:

```go
Requirements: detection.DetectorRequirements{
	Enrichments: []detection.EnrichmentRequirement{
		{
			Name:       "exec-env",
			Dependency: detection.DependencyRequired,
		},
		{
			Name:       "exec-hash",
			Dependency: detection.DependencyOptional,
			Config:     "inode",  // Specific hash mode
		},
	},
},
```

**Available enrichments**:
- `"exec-env"` - Environment variables (`--output exec-env`)
- `"exec-hash"` - File hashes (`--output exec-hash`)

**Hash modes** (for `exec-hash`):
- `"inode"` - Hash by inode
- `"dev-inode"` - Hash by device and inode
- `"digest-inode"` - SHA256 + inode

**Engine behavior**:
- **Required**: Registration fails if enrichment not enabled
- **Optional**: Warns if unavailable, detector proceeds

### Architecture Filtering

Restrict detector to specific CPU architectures:

```go
Requirements: detection.DetectorRequirements{
	Architectures: []string{"amd64", "arm64"},
},
```

**Values** (use Go's GOARCH format):
- `"amd64"` - x86-64 (Intel/AMD 64-bit)
- `"arm64"` - AArch64 (ARM 64-bit)

**Empty slice** = supports all architectures (default)

**When to use**:
- Architecture-specific syscall numbers
- Assembly code analysis
- CPU feature detection
- Platform-specific behavior

### Tracee Version Constraints

Declare Tracee version compatibility:

```go
Requirements: detection.DetectorRequirements{
	MinTraceeVersion: &v1beta1.Version{Major: 0, Minor: 20, Patch: 0},
	MaxTraceeVersion: &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
},
```

**Semantics**:
- `MinTraceeVersion`: Inclusive (>=)
- `MaxTraceeVersion`: Exclusive (<)

**Example scenarios**:
```go
// Requires Tracee 0.20.0+
MinTraceeVersion: &v1beta1.Version{Major: 0, Minor: 20, Patch: 0}

// Works up to Tracee 1.0.0 (exclusive)
MaxTraceeVersion: &v1beta1.Version{Major: 1, Minor: 0, Patch: 0}

// Works with Tracee 0.20.x through 0.x (x < 1.0)
MinTraceeVersion: &v1beta1.Version{Major: 0, Minor: 20, Patch: 0},
MaxTraceeVersion: &v1beta1.Version{Major: 1, Minor: 0, Patch: 0}
```

### Configuration (Future Feature)

Configuration support is planned for future releases:

**Phase 1 (Current)**: Hardcode defaults in `Init()`
```go
type MyDetector struct {
	threshold int  // Hardcoded default
}

func (d *MyDetector) Init(params detection.DetectorParams) error {
	d.threshold = 10  // Default value
	return nil
}
```

**Phase 2 (Future)**: Policy-based configuration
```yaml
# tracee-policy.yaml (future)
rules:
  - event: my_detection
    action: audit
    parameters:
      threshold: 15
      sensitivity: high
```

```go
func (d *MyDetector) Init(params detection.DetectorParams) error {
	// Engine extracts parameters from policy
	d.threshold = params.Config.GetInt("threshold", 10)  // Default: 10
	d.sensitivity = params.Config.GetString("sensitivity", "medium")

	// Validate
	if d.threshold < 1 || d.threshold > 100 {
		return fmt.Errorf("threshold must be 1-100")
	}

	return nil
}
```

**Document your configuration**:
```go
// Config: threshold (int, default: 10, range: 1-100)
// Config: sensitivity (string, default: "medium", values: low|medium|high)
type MyDetector struct {
	threshold   int
	sensitivity string
}
```

---

## Lifecycle Management

### Init() Best Practices

`Init()` is called once during detector registration, before any events are processed.

**What to do in Init()**:
- Store references to logger, datastores
- Initialize internal state (maps, caches, LRU)
- Validate configuration
- Acquire resources (connections, files)
- Check datastore availability

**Example**:
```go
func (d *MyDetector) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.dataStores = params.DataStores

	// Initialize LRU cache
	var err error
	d.cache, err = lru.New[string, int](1000)
	if err != nil {
		return fmt.Errorf("failed to create cache: %w", err)
	}

	// Validate requirements
	if d.dataStores.Processes() == nil {
		return fmt.Errorf("process store required but not available")
	}

	// Optional: Check for optional features
	if d.dataStores.System() == nil {
		d.logger.Warnw("System store unavailable, some features disabled")
	}

	d.logger.Infow("Detector initialized",
		"cache_size", 1000,
		"features", "process_analysis")

	return nil
}
```

**What NOT to do in Init()**:
- Don't block for long periods (Init must return quickly)
- Don't panic (return errors instead)
- Don't forget to implement Close() if you start goroutines or acquire resources

### Close() for Cleanup

Implement the `DetectorCloser` interface if your detector needs cleanup:

```go
type DetectorCloser interface {
	EventDetector
	Close() error
}
```

**When to implement Close()**:
- Release file handles, network connections
- Stop background goroutines
- Flush caches, close databases
- Free expensive resources

**Example**:
```go
type MyDetector struct {
	logger     detection.Logger
	ticker     *time.Ticker
	done       chan struct{}
	cache      *lru.Cache[string, int]
	connection *sql.DB
}

func (d *MyDetector) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.done = make(chan struct{})

	// Initialize resources
	var err error
	d.cache, err = lru.New[string, int](1000)
	if err != nil {
		return err
	}

	d.connection, err = sql.Open("sqlite3", "/tmp/detector.db")
	if err != nil {
		return err
	}

	// Start background goroutine
	d.ticker = time.NewTicker(5 * time.Minute)
	go d.periodicCleanup()

	return nil
}

func (d *MyDetector) Close() error {
	d.logger.Infow("Shutting down detector")

	// Stop background goroutine
	d.ticker.Stop()
	close(d.done)

	// Close database connection
	if err := d.connection.Close(); err != nil {
		return fmt.Errorf("failed to close database: %w", err)
	}

	d.logger.Infow("Detector closed")
	return nil
}

func (d *MyDetector) periodicCleanup() {
	for {
		select {
		case <-d.ticker.C:
			// Periodic cleanup
			d.cache.Purge()
		case <-d.done:
			return
		}
	}
}
```

**Close() must be idempotent** (safe to call multiple times):
```go
func (d *MyDetector) Close() error {
	if d.ticker != nil {
		d.ticker.Stop()
		d.ticker = nil  // Prevent double-close
	}

	if d.connection != nil {
		err := d.connection.Close()
		d.connection = nil
		return err
	}

	return nil
}
```

### Error Handling Guidelines

**Return nil, nil** (skip event):
- Optional event field missing
- Event doesn't match detection logic
- Transient enrichment failure (log warning)

**Return nil, error** (critical error):
- Required event field missing
- Datastore unavailable/unhealthy
- Configuration invalid
- Resource exhaustion

**Example**:
```go
func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Optional field - return nil, nil if missing
	pathname, found := v1beta1.GetData[string](event, "pathname")
	if !found {
		return nil, nil  // Skip this event silently
	}

	// Critical field - return error if missing
	flags, err := v1beta1.GetDataSafe[int32](event, "flags")
	if err != nil {
		return nil, fmt.Errorf("missing required field: %w", err)
	}

	// Transient failure - log and skip
	proc, err := d.dataStores.Processes().GetProcess(entityId)
	if errors.Is(err, datastores.ErrNotFound) {
		d.logger.Warnw("Process not found, skipping",
			"entity_id", entityId)
		return nil, nil  // Graceful degradation
	}

	// Critical failure - return error
	if d.dataStores.Processes() == nil {
		return nil, fmt.Errorf("process store unavailable")
	}

	// Detection logic...
}
```

**Engine behavior**:
- Errors are logged, counted in metrics
- Errors never stop the pipeline
- Detector continues processing next event

---

## Testing

### Unit Testing Patterns

Unit tests validate detector logic in isolation:

```go
func TestMyDetector_OnEvent(t *testing.T) {
	// Create detector
	detector := &MyDetector{}

	// Mock logger
	logger := &testLogger{}

	// Initialize
	params := detection.DetectorParams{
		Logger: logger,
		// DataStores: mock datastores if needed
	}
	err := detector.Init(params)
	require.NoError(t, err)

	// Create test event
	event := &v1beta1.Event{
		Name: "security_file_open",
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/etc/shadow"),
			v1beta1.NewInt32Value("flags", 1),
		},
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				EntityId: &wrapperspb.UInt32Value{Value: 123},
				Pid:      &wrapperspb.UInt32Value{Value: 5678},
			},
		},
	}

	// Call OnEvent
	outputs, err := detector.OnEvent(context.Background(), event)
	require.NoError(t, err)
	require.Len(t, outputs, 1)

	// Verify output
	output := outputs[0]
	assert.NotNil(t, output.Data)

	// Verify data fields
	pathname, found := v1beta1.GetData[string](&v1beta1.Event{Data: output.Data}, "file_path")
	assert.True(t, found)
	assert.Equal(t, "/etc/shadow", pathname)
}
```

### Mock DataStores

For unit tests, you can create simple mock datastores. Here's a minimal example:

```go
func TestDetectorWithDataStore(t *testing.T) {
	// Create a mock registry that returns nil for all stores
	// (or implement minimal mocks for stores your detector uses)
	mockRegistry := &mockDataStoreRegistry{
		processData: map[uint64]*datastores.ProcessInfo{
			123: {EntityID: 123, PID: 5678, Name: "bash", Exe: "/usr/bin/bash"},
		},
	}

	// Initialize detector with mock
	detector := &MyDetector{}
	params := detection.DetectorParams{
		Logger:     &testLogger{},
		DataStores: mockRegistry,
	}
	err := detector.Init(params)
	require.NoError(t, err)

	// Test detector logic...
}
```

---

## Observability

### Prometheus Metrics

Tracee automatically exports per-detector metrics:

**Counter metrics** (total counts):
```
detector_events_received_total{detector_id="TRC-001"}    # Events dispatched to detector
detector_events_matched_total{detector_id="TRC-001"}     # Events that produced output
detector_errors_total{detector_id="TRC-001"}             # Errors returned by OnEvent()
```

**Histogram metric** (latency distribution):
```
detector_duration_seconds{detector_id="TRC-001"}         # OnEvent() processing time
```

**View metrics**:
```bash
# Enable metrics in Tracee
sudo ./dist/tracee --metrics

# Query Prometheus endpoint
curl http://localhost:3366/metrics | grep detector_
```

**Example metrics**:
```
detector_events_received_total{detector_id="TRC-001"} 1234
detector_events_matched_total{detector_id="TRC-001"} 42
detector_errors_total{detector_id="TRC-001"} 0
detector_duration_seconds{detector_id="TRC-001",quantile="0.5"} 0.000123
detector_duration_seconds{detector_id="TRC-001",quantile="0.95"} 0.000456
detector_duration_seconds{detector_id="TRC-001",quantile="0.99"} 0.001234
```

### Debug Logging Patterns

Use structured logging with key-value pairs:

```go
func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]*v1beta1.Event, error) {
	// Debug: Trace event processing
	d.logger.Debugw("Processing event",
		"event_name", event.Name,
		"entity_id", event.Workload.Process.EntityId.Value,
		"pid", v1beta1.GetProcessPid(event))

	// Debug: Detection triggered (event output already captures this)
	d.logger.Debugw("Detection triggered",
		"file", pathname,
		"process", processName,
		"confidence", 95)

	// Warn: Recoverable issues
	d.logger.Warnw("Process not found, using default",
		"entity_id", entityId,
		"default_name", "unknown")

	// Error: Critical issues
	d.logger.Errorw("Failed to query datastore",
		"error", err,
		"operation", "GetProcess",
		"entity_id", entityId)

	// ...
}
```

**Enable debug logging**:
```bash
# All detectors
sudo ./dist/tracee --log debug
```

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

**After** (new detector):
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

### Migration Checklist

- [ ] Change package from `main` to `detectors`
- [ ] Add `init() { register(&YourDetector{}) }`
- [ ] Update imports to `api/v1beta1` packages
- [ ] Replace `detect.Signature` with `detection.EventDetector`
- [ ] Combine `GetMetadata()` + `GetSelectedEvents()` → `GetDefinition()`
- [ ] Move data filters from `OnEvent()` to `EventRequirement.DataFilters`
- [ ] Replace `protocol.Event` casting with `*v1beta1.Event` parameter
- [ ] Replace manual `Args` loop with `GetData[T]()` / `GetDataSafe[T]()`
- [ ] Replace `ctx.Callback()` with synchronous `return []detection.DetectorOutput{}`
- [ ] Return `DetectorOutput` with `Data` fields instead of full `v1beta1.Event`
- [ ] Add `AutoPopulateFields` for automatic enrichment
- [ ] Update tests to call `OnEvent()` directly and verify `DetectorOutput`
- [ ] Remove `Close()` if empty (optional interface)

### Common Pattern Translations

**Pattern: Event Selection**
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

**Pattern: Data Extraction**
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

**Pattern: Filtering**
```go
// Before (in OnEvent)
if !strings.HasPrefix(pathname, "/etc/") {
	return nil  // Manual filter
}

// After (in EventRequirement)
DataFilters: []string{"pathname=/etc/*"},  // Engine filters before dispatch
```

**Pattern: Callback → Return**
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

---

## Best Practices

### Detector Design Principles

**Single Responsibility**: Each detector should have one clear purpose.

✅ **Good**: `SensitiveFileAccessDetector` - detects access to sensitive files
❌ **Bad**: `FileDetector` - detects file access, modifications, and deletions

**Declarative Configuration**: Use EventRequirements for filtering, not OnEvent() logic.

✅ **Good**:
```go
EventRequirement{
	Name:         "openat",
	DataFilters:  []string{"pathname=/etc/*"},
	ScopeFilters: []string{"container=started"},
}
```

❌ **Bad**:
```go
func OnEvent(...) {
	if !strings.HasPrefix(pathname, "/etc/") {
		return nil, nil
	}
	if containerID == "" || isNewContainer {
		return nil, nil
	}
	// ...
}
```

**Fail Fast**: Return errors early for invalid state, continue for skippable events.

✅ **Good**:
```go
func OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Critical field missing - error
	pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
	if err != nil {
		return nil, err
	}

	// Optional enrichment failed - log and continue
	proc, err := d.dataStores.Processes().GetProcess(entityId)
	if errors.Is(err, datastores.ErrNotFound) {
		d.logger.Debugw("Process not found, continuing without process context")
	}

	// Detection logic...
}
```

**Immutable Threat Metadata**: Never modify Threat at runtime.

✅ **Good**: Use Event.Data for runtime context
❌ **Bad**: Modify Threat.Properties at runtime

### Performance Considerations

**Minimize allocations in hot path**:
```go
// Pre-allocate slices with capacity
detection.Data = make([]*v1beta1.EventData, 0, 5)

// Reuse buffers
var buf strings.Builder
buf.WriteString(...)

// Use LRU caches for state
cache, _ := lru.New[string, int](1000)
```

**Avoid expensive operations**:
```go
// ❌ Expensive: Query process ancestry on every event
ancestry, _ := d.dataStores.Processes().GetAncestry(entityId, 10)

// ✅ Better: Use AutoPopulate.ProcessAncestry (only when needed)
AutoPopulate: detection.AutoPopulateFields{
	ProcessAncestry: true,  // Engine handles optimization
}

// ✅ Best: Only enable if you actually use ancestry
AutoPopulate: detection.AutoPopulateFields{
	ProcessAncestry: false,  // Don't query if not needed
}
```

**Batch operations when possible**:
```go
// ❌ Slow: Individual lookups
for _, addr := range addresses {
	symbol, _ := d.dataStores.KernelSymbols().ResolveSymbolByAddress(addr)
	// Process symbol
}

// ✅ Fast: Batch lookup
symbols, _ := d.dataStores.KernelSymbols().ResolveSymbolsBatch(addresses)
for addr, symbol := range symbols {
	// Process symbol
}
```

### Error Handling Patterns

**Classify errors correctly**:

**Skippable (return nil, nil)**:
- Optional field missing
- Process not in tree (exited)
- Event doesn't match logic
- Transient enrichment failure

**Critical (return nil, error)**:
- Required field missing
- Datastore unavailable
- Invalid state/corruption
- Resource exhaustion

**Example**:
```go
func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Skippable: Optional field
	description, found := v1beta1.GetData[string](event, "description")
	if !found {
		d.logger.Debugw("Description field missing, using default")
		description = "unknown"
	}

	// Skippable: Transient failure
	proc, err := d.dataStores.Processes().GetProcess(entityId)
	if errors.Is(err, datastores.ErrNotFound) {
		d.logger.Warnw("Process not found, skipping enrichment")
		// Continue without process context
	}

	// Critical: Required field
	pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
	if err != nil {
		return nil, fmt.Errorf("missing required field: %w", err)
	}

	// Critical: Datastore unavailable
	if d.dataStores.Processes() == nil {
		return nil, fmt.Errorf("process store required but unavailable")
	}

	// Detection logic...
}
```

### Code Organization

**Detector structure**:
```go
package detectors

import (
	// Standard library
	"context"
	"fmt"
	"strings"

	// Third-party
	lru "github.com/hashicorp/golang-lru/v2"

	// Tracee API
	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

// Auto-register
func init() {
	register(&MyDetector{})
}

// Detector struct - state
type MyDetector struct {
	// Dependencies (from DetectorParams)
	logger     detection.Logger
	dataStores datastores.Registry

	// Detector state
	cache      *lru.Cache[string, int]
	threshold  int
}

// GetDefinition - static definition
func (d *MyDetector) GetDefinition() detection.DetectorDefinition {
	// ...
}

// Init - initialization
func (d *MyDetector) Init(params detection.DetectorParams) error {
	// ...
}

// OnEvent - detection logic
func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// ...
}

// Close - cleanup (optional)
func (d *MyDetector) Close() error {
	// ...
}

// Helper methods (private)
func (d *MyDetector) analyzePattern(data string) bool {
	// ...
}
```

**File naming**: `<detector_name>.go` (snake_case)
- `sensitive_file_access.go`
- `process_injection.go`
- `hooked_syscall.go`

---

## Examples

### Example 1: Simple Threat Detector

See `detectors/example_detector.go` in the Tracee repository for a complete, well-documented example.

### Example 2: Real Detectors

The Tracee codebase includes several real detector implementations you can learn from:

**Threat Detectors**:
- `hooked_syscall.go` - Syscall table hook detection (rootkit)
- `proc_kcore_read.go` - Kernel memory access detection
- `anti_debugging_ptraceme.go` - Anti-debugging detection
- `aslr_inspection.go` - ASLR bypass detection
- `hidden_file_created.go` - Hidden file creation detection

**Derived Event Detectors**:
- `hooked_seq_ops.go` - Sequence operations hooking (derived event)

**Key patterns to study**:

1. **Using KernelSymbolStore** (`hooked_syscall.go`):
```go
// Batch resolve addresses
symbols, err := d.dataStores.KernelSymbols().ResolveSymbolsBatch(addresses)
for addr, symbolList := range symbols {
	for _, symbol := range symbolList {
		if symbol.Module != "system" {
			// Hook detected
		}
	}
}
```

2. **Using SyscallStore** (`hooked_syscall.go`):
```go
syscallName, err := d.dataStores.Syscalls().GetSyscallName(syscallID)
if errors.Is(err, datastores.ErrNotFound) {
	d.logger.Warnw("Unknown syscall", "id", syscallID)
	syscallName = fmt.Sprintf("syscall_%d", syscallID)
}
```

3. **LRU Cache for Deduplication** (`hooked_syscall.go`):
```go
// Initialize in Init()
d.reportedHooks, err = lru.New[int32, uint64](d.maxSysCallTableSize)

// Use in OnEvent() to prevent duplicate alerts
previousAddr, seen := d.reportedHooks.Get(syscallID)
if seen && previousAddr == currentAddr {
	return nil, nil  // Already reported this hook
}
d.reportedHooks.Add(syscallID, currentAddr)
```

4. **Multiple DataStores** (`hooked_syscall.go`):
```go
Requirements: detection.DetectorRequirements{
	DataStores: []detection.DataStoreRequirement{
		{Name: "symbol", Dependency: detection.DependencyRequired},
		{Name: "syscall", Dependency: detection.DependencyRequired},
	},
},
```

5. **Structured Output Fields** (`hooked_syscall.go`):
```go
Fields: []*v1beta1.EventField{
	{Name: "syscall", Type: "const char*"},
	{Name: "address", Type: "const char*"},
	{Name: "function", Type: "const char*"},
	{Name: "owner", Type: "const char*"},
},
```

### Example 3: Detector with Process Ancestry

```go
package detectors

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() {
	register(&PrivilegeEscalationDetector{})
}

type PrivilegeEscalationDetector struct {
	logger     detection.Logger
	dataStores datastores.Registry
}

func (d *PrivilegeEscalationDetector) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-102",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name: "setuid",
					DataFilters: []string{"uid=0"},  // Becoming root
				},
			},
			DataStores: []detection.DataStoreRequirement{
				{Name: "process", Dependency: detection.DependencyRequired},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "privilege_escalation",
			Description: "Non-root process became root",
			Version:     &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
			Fields: []*v1beta1.EventField{
				{Name: "process", Type: "const char*"},
				{Name: "old_uid", Type: "int"},
				{Name: "new_uid", Type: "int"},
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Privilege Escalation",
			Description: "Process escalated privileges to root",
			Severity:    v1beta1.Severity_HIGH,
			Mitre: &v1beta1.Mitre{
				Tactic:    &v1beta1.MitreTactic{Name: "Privilege Escalation"},
				Technique: &v1beta1.MitreTechnique{Id: "T1548", Name: "Abuse Elevation Control Mechanism"},
			},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:          true,
			DetectedFrom:    true,
			ProcessAncestry: true,  // Get full ancestry chain
		},
	}
}

func (d *PrivilegeEscalationDetector) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.dataStores = params.DataStores
	return nil
}

func (d *PrivilegeEscalationDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Get process information
	entityId := event.Workload.Process.EntityId.Value
	proc, err := d.dataStores.Processes().GetProcess(entityId)
	if errors.Is(err, datastores.ErrNotFound) {
		return nil, nil
	}

	// Check if this is an escalation (was non-root, now root)
	oldUID, _ := v1beta1.GetData[uint32](event, "old_uid")
	newUID, _ := v1beta1.GetData[uint32](event, "new_uid")

	if oldUID == 0 || newUID != 0 {
		return nil, nil  // Not an escalation
	}

	return []detection.DetectorOutput{{
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("process", proc.Exe),
			v1beta1.NewUInt32Value("old_uid", oldUID),
			v1beta1.NewUInt32Value("new_uid", newUID),
		},
		// ProcessAncestry auto-populated by engine
		// Output will include full 5-level ancestry for forensics
	}}, nil
}
```

---

## Conclusion

You now have everything you need to write powerful, efficient, and maintainable threat detectors for Tracee. Key takeaways:

1. **Start simple**: Use the Quick Start example to get going
2. **Use declarative features**: EventRequirements, AutoPopulateFields
3. **Access rich context**: DataStores provide full system state
4. **Follow best practices**: Type safety, error handling, performance
5. **Learn from examples**: Study real detectors in the codebase
6. **Test thoroughly**: Unit tests with mocks, integration tests with real components

**Next steps**:
- Read the [DataStore API Reference](datastore-api.md) for complete API documentation
- Explore example detectors in `detectors/` directory
- Join the Tracee community for questions and discussions

Happy detecting! 🔍
