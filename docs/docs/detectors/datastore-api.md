# DataStore API Reference

Complete API reference for Tracee's DataStore system. This provides read-only access to system state information for detectors.

## Table of Contents

1. [Overview](#overview)
2. [Core Concepts](#core-concepts)
3. [Registry Interface](#registry-interface)
4. [ProcessStore](#processstore)
5. [ContainerStore](#containerstore)
6. [SystemStore](#systemstore)
7. [SyscallStore](#syscallstore)
8. [KernelSymbolStore](#kernelsymbolstore)
9. [DNSStore](#dnsstore)
10. [Health and Metrics](#health-and-metrics)
11. [Error Handling](#error-handling)
12. [Advanced Usage](#advanced-usage)
13. [Writable DataStores](#writable-datastores)
14. [Summary](#summary)

---

## Overview

### What DataStores Provide

DataStores give detectors read-only access to system state information collected by Tracee:

- **Process Tree**: Process information, ancestry, and relationships
- **Container Registry**: Container metadata, Kubernetes pod information
- **System Information**: Immutable system details (architecture, kernel, OS)
- **Syscall Mapping**: Syscall ID ↔ name conversion
- **Kernel Symbols**: Symbol resolution for addresses
- **DNS Cache**: DNS query responses

### Registry Pattern

All datastores are accessed through a single `Registry` interface provided to detectors via `DetectorParams`:

{% raw %}
```go
func (d *MyDetector) Init(params detection.DetectorParams) error {
    d.dataStores = params.DataStores  // Registry interface

    // Access individual stores
    processStore := d.dataStores.Processes()
    containerStore := d.dataStores.Containers()

    return nil
}
```
{% endraw %}

### Read-Only Access Model

DataStores are **read-only** from the detector perspective:

- ✅ Query existing data
- ✅ Iterate over collections
- ✅ Check health and metrics
- ❌ No writes or modifications
- ❌ No data deletion

The engine manages datastore lifecycle (initialization, updates, shutdown).

### Thread Safety Guarantees

All datastores are **thread-safe** for concurrent access:

- Multiple detectors can query the same store simultaneously
- No locking required in detector code
- Internal RWMutex protects shared state

---

## Core Concepts

### DataStore Base Interface

All datastores implement this base interface:

{% raw %}
```go
type DataStore interface {
    // Name returns the name of this datastore
    Name() string

    // GetHealth returns the current health status
    GetHealth() *HealthInfo

    // GetMetrics returns operational metrics
    GetMetrics() *DataStoreMetrics
}
```
{% endraw %}

### Common Errors

Sentinel errors for standard error cases:

{% raw %}
```go
var (
    ErrNotFound        = errors.New("entity not found")
    ErrStoreUnhealthy  = errors.New("datastore is unhealthy")
    ErrNotImplemented  = errors.New("operation not implemented")
    ErrInvalidArgument = errors.New("invalid argument")
)
```
{% endraw %}

**StoreError** wraps errors with context:

{% raw %}
```go
type StoreError struct {
    StoreName string  // Which store
    Operation string  // Which operation
    Err       error   // Underlying error
}
```
{% endraw %}

### Health Status

{% raw %}
```go
type HealthStatus int

const (
    HealthUnknown   HealthStatus = iota  // 0: Unknown state
    HealthHealthy                        // 1: Operating normally
    HealthUnhealthy                      // 2: Degraded or unavailable
)
```
{% endraw %}

---

## Registry Interface

### Registry Methods

{% raw %}
```go
type Registry interface {
    // Core stores (always return non-nil, but may be unavailable)
    Processes() ProcessStore
    Containers() ContainerStore
    KernelSymbols() KernelSymbolStore
    DNS() DNSStore
    System() SystemStore
    Syscalls() SyscallStore

    // Custom stores (returns error if not found)
    GetCustom(name string) (DataStore, error)

    // Introspection
    List() []string
    IsAvailable(name string) bool
    GetMetadata(name string) (*DataStoreMetadata, error)
    GetMetrics(name string) (*DataStoreMetrics, error)
}
```
{% endraw %}

**Nil-Safety Guarantee:**

Accessor methods (`Processes()`, `Containers()`, etc.) **never return nil**. If a store is not registered or unavailable, they return a null object that:

- Implements the store interface
- Returns `ErrStoreUnhealthy` for all operations
- Has health status set to `HealthUnhealthy`

This eliminates nil checks and allows safe method chaining:

```go
// Always safe - no nil check needed
proc, err := datastores.Processes().GetProcess(entityID)
if errors.Is(err, datastores.ErrStoreUnhealthy) {
    // Store not available
}
if errors.Is(err, datastores.ErrNotFound) {
    // Process not found
}
```

### Usage Examples

**Basic access**:
{% raw %}
```go
// Direct access to core stores
processStore := d.dataStores.Processes()
containerStore := d.dataStores.Containers()

// Use immediately
proc, err := processStore.GetProcess(entityId)
if errors.Is(err, datastores.ErrNotFound) {
    // Process not found
}
```
{% endraw %}

**Check availability**:
{% raw %}
```go
// Check if optional store is available
if d.dataStores.IsAvailable("system") {
    systemStore := d.dataStores.System()
    sysInfo := systemStore.GetSystemInfo()
    // Use system info
}
```
{% endraw %}

**List all stores**:
{% raw %}
```go
stores := d.dataStores.List()
d.logger.Infow("Available datastores", "stores", stores)
// Output: ["process", "container", "symbol", "dns", "system", "syscall"]
```
{% endraw %}

**Get store metadata**:
{% raw %}
```go
metadata, err := d.dataStores.GetMetadata("process")
if err == nil {
    d.logger.Infow("Process store info",
        "name", metadata.Name,
        "description", metadata.Description)
}
```
{% endraw %}

---

## ProcessStore

### Interface

{% raw %}
```go
type ProcessStore interface {
    DataStore

    // GetProcess retrieves process information by entity ID
    // Returns ErrNotFound if not found
    GetProcess(entityId uint32) (*ProcessInfo, error)

    // GetChildProcesses returns all child processes
    // Returns empty slice if no children
    GetChildProcesses(entityId uint32) ([]*ProcessInfo, error)

    // GetAncestry retrieves the ancestry chain up to maxDepth levels
    // [0] = process itself, [1] = parent, [2] = grandparent, etc.
    // Returns empty slice if maxDepth <= 0 or process not found
    GetAncestry(entityId uint32, maxDepth int) ([]*ProcessInfo, error)
}
```
{% endraw %}

### ProcessInfo Structure

{% raw %}
```go
type ProcessInfo struct {
    EntityID  uint32    // Primary key (hash) - matches Event.Process.EntityId
    PID       uint32    // OS process ID (for display/logging)
    PPID      uint32    // OS parent PID (for display/logging)
    Name      string    // Binary name: "bash"
    Exe       string    // Full executable path: "/usr/bin/bash"
    StartTime time.Time // Process start time
    UID       uint32    // User ID
    GID       uint32    // Group ID
}
```
{% endraw %}

### Methods

#### GetProcess

Retrieve process information by entity ID.

**Signature**:
{% raw %}
```go
GetProcess(entityId uint32) (*ProcessInfo, error)
```
{% endraw %}

**Parameters**:

- `entityId`: Process entity ID (hash from ProcessTree, matches `event.Workload.Process.EntityId`)

**Returns**:

- `*ProcessInfo`: Process information if found
- `error`: `ErrNotFound` if not found, `nil` on success

**Example**:
{% raw %}
```go
entityId := event.Workload.Process.EntityId.Value
proc, err := d.dataStores.Processes().GetProcess(entityId)
if errors.Is(err, datastores.ErrNotFound) {
    d.logger.Warnw("Process not found", "entity_id", entityId)
    return nil, nil
}
if err != nil {
    return nil, fmt.Errorf("failed to get process: %w", err)
}

d.logger.Infow("Found process",
    "pid", proc.PID,           // OS PID for logging
    "name", proc.Name,         // "bash"
    "exe", proc.Exe,           // "/usr/bin/bash"
    "uid", proc.UID,
    "start_time", proc.StartTime)
```
{% endraw %}

#### GetAncestry

Retrieve process ancestry chain up to specified depth.

**Signature**:
{% raw %}
```go
GetAncestry(entityId uint32, maxDepth int) ([]*ProcessInfo, error)
```
{% endraw %}

**Parameters**:

- `entityId`: Process entity ID
- `maxDepth`: Maximum ancestry depth (typically 5)

**Returns**:

- `[]*ProcessInfo`: Ancestry chain where `[0]` = process itself, `[1]` = parent, `[2]` = grandparent, etc.
- `error`: Error if query fails

**Behavior**:

- Returns empty slice if `maxDepth <= 0`
- Returns empty slice if process not found
- Stops if parent not found in tree
- Stops if circular reference detected

**Example**:
{% raw %}
```go
ancestry, err := d.dataStores.Processes().GetAncestry(entityId, 5)
if err != nil {
    return nil, fmt.Errorf("failed to get ancestry: %w", err)
}

if len(ancestry) == 0 {
    d.logger.Debugw("No ancestry found")
    return nil, nil
}

// ancestry[0] is the process itself
// ancestry[1] is the parent
// ancestry[2] is the grandparent, etc.

for i, ancestor := range ancestry {
    d.logger.Debugw("Ancestor",
        "level", i,
        "pid", ancestor.PID,
        "name", ancestor.Name,
        "exe", ancestor.Exe)
}

// Check if parent is suspicious
if len(ancestry) > 1 {
    parent := ancestry[1]
    if strings.Contains(parent.Exe, "suspicious") {
        // Trigger detection
    }
}
```
{% endraw %}

#### GetChildProcesses

Retrieve all child processes of a given process.

**Signature**:
{% raw %}
```go
GetChildProcesses(entityId uint32) ([]*ProcessInfo, error)
```
{% endraw %}

**Parameters**:

- `entityId`: Parent process entity ID

**Returns**:

- `[]*ProcessInfo`: List of child processes (empty if no children)
- `error`: Error if query fails

**Example**:
{% raw %}
```go
children, err := d.dataStores.Processes().GetChildProcesses(entityId)
if err != nil {
    return nil, err
}

d.logger.Infow("Process has children", "count", len(children))
for _, child := range children {
    d.logger.Debugw("Child process",
        "pid", child.PID,
        "name", child.Name,
        "exe", child.Exe)
}
```
{% endraw %}

### EntityID vs PID

!!! Important "Always Use EntityID for Lookups"
    **EntityID** is the primary key for process lookups, not PID.

    **Why?**

    - PIDs can be reused after a process exits
    - EntityID is unique for the lifetime of the process
    - EntityID matches `event.Workload.Process.EntityId`

    **Usage**:

    - **EntityID**: For all datastore lookups (`GetProcess`, `GetAncestry`, etc.)
    - **PID**: Only for display, logging, and debugging

**Correct**:
{% raw %}
```go
// Get EntityID from event
entityId := event.Workload.Process.EntityId.Value

// Use EntityID for lookup
proc, err := d.dataStores.Processes().GetProcess(entityId)
if errors.Is(err, datastores.ErrNotFound) {
    return nil, nil
}

// Use PID for logging only
d.logger.Infow("Process found", "pid", proc.PID, "name", proc.Name)
```
{% endraw %}

**Incorrect**:
{% raw %}
```go
// ❌ Don't use PID for lookups
pid := event.Workload.Process.Pid.Value
proc, err := d.dataStores.Processes().GetProcess(uint32(pid))  // Wrong!
```
{% endraw %}

---

## ContainerStore

### Interface

{% raw %}
```go
type ContainerStore interface {
    DataStore

    // GetContainer retrieves container by ID
    // Returns ErrNotFound if not found
    GetContainer(id string) (*ContainerInfo, error)

    // GetContainerByName retrieves container by name
    // Returns ErrNotFound if not found
    GetContainerByName(name string) (*ContainerInfo, error)
}
```
{% endraw %}

### ContainerInfo Structure

{% raw %}
```go
type ContainerInfo struct {
    ID          string      // Container ID
    Name        string      // Container name
    Image       string      // Container image
    ImageDigest string      // Image digest (SHA256)
    Runtime     string      // Runtime: "docker", "containerd", "crio"
    StartTime   time.Time   // Container start time
    Pod         *K8sPodInfo // Kubernetes pod info (nil for non-K8s)
}

type K8sPodInfo struct {
    Name      string // Pod name
    UID       string // Pod UID
    Namespace string // Pod namespace
    Sandbox   bool   // Whether this is a sandbox container
}
```
{% endraw %}

### Methods

#### GetContainer

Retrieve container information by container ID.

**Signature**:
{% raw %}
```go
GetContainer(id string) (*ContainerInfo, error)
```
{% endraw %}

**Parameters**:

- `id`: Container ID (full ID or short form)

**Returns**:

- `*ContainerInfo`: Container information if found
- `error`: `ErrNotFound` if not found, `nil` on success

**Example**:
{% raw %}
```go
containerID := v1beta1.GetContainerID(event)
if containerID == "" {
    // Not a container event
    return nil, nil
}

container, err := d.dataStores.Containers().GetContainer(containerID)
if errors.Is(err, datastores.ErrNotFound) {
    d.logger.Warnw("Container not found", "id", containerID)
    return nil, nil
}
if err != nil {
    return nil, fmt.Errorf("failed to get container: %w", err)
}

d.logger.Infow("Container info",
    "id", container.ID,
    "name", container.Name,
    "image", container.Image,
    "runtime", container.Runtime,
    "start_time", container.StartTime)

// Access Kubernetes pod information
if container.Pod != nil {
    d.logger.Infow("Pod info",
        "name", container.Pod.Name,
        "namespace", container.Pod.Namespace,
        "uid", container.Pod.UID,
        "sandbox", container.Pod.Sandbox)
}
```
{% endraw %}

#### GetContainerByName

Retrieve container information by container name.

**Signature**:
{% raw %}
```go
GetContainerByName(name string) (*ContainerInfo, error)
```
{% endraw %}

**Parameters**:

- `name`: Container name

**Returns**:

- `*ContainerInfo`: Container information if found
- `error`: `ErrNotFound` if not found, `nil` on success

**Example**:
{% raw %}
```go
container, err := d.dataStores.Containers().GetContainerByName("web-server")
if errors.Is(err, datastores.ErrNotFound) {
    d.logger.Debugw("Container not found", "name", "web-server")
    return nil, nil
}
if err != nil {
    return nil, fmt.Errorf("failed to get container: %w", err)
}

d.logger.Infow("Found container by name",
    "name", container.Name,
    "id", container.ID,
    "image", container.Image)
```
{% endraw %}

---

## SystemStore

### Interface

{% raw %}
```go
type SystemStore interface {
    DataStore

    // GetSystemInfo returns immutable system information
    // Collected at Tracee startup, never changes
    GetSystemInfo() *SystemInfo
}
```
{% endraw %}

### SystemInfo Structure

{% raw %}
```go
type SystemInfo struct {
    Architecture    string            // CPU architecture: "x86_64", "aarch64"
    KernelRelease   string            // Kernel version: "5.15.0-generic"
    Hostname        string            // System hostname
    BootTime        time.Time         // System boot time
    TraceeStartTime time.Time         // When Tracee started
    OSName          string            // OS name: "Ubuntu"
    OSVersion       string            // OS version: "22.04"
    OSPrettyName    string            // Full OS name: "Ubuntu 22.04 LTS"
    TraceeVersion   string            // Tracee version string
    InitNamespaces  map[string]uint32 // Init process namespaces
}
```
{% endraw %}

### Methods

#### GetSystemInfo

Retrieve immutable system information.

**Signature**:
{% raw %}
```go
GetSystemInfo() *SystemInfo
```
{% endraw %}

**Returns**:

- `*SystemInfo`: System information (never nil if store available)

**Characteristics**:

- **Immutable**: Data never changes during Tracee lifetime
- **Fast**: No lookup, just returns cached data
- **Always available**: Returns immediately with no errors

**Example**:
{% raw %}
```go
// System store always returns non-nil (per registry contract)
// Check IsAvailable() if you need to verify store is ready
systemStore := d.dataStores.System()
sysInfo := systemStore.GetSystemInfo()

d.logger.Infow("System information",
    "arch", sysInfo.Architecture,
    "kernel", sysInfo.KernelRelease,
    "os", sysInfo.OSPrettyName,
    "hostname", sysInfo.Hostname,
    "tracee_version", sysInfo.TraceeVersion,
    "boot_time", sysInfo.BootTime,
    "tracee_start", sysInfo.TraceeStartTime)

// Check architecture for platform-specific logic
if sysInfo.Architecture == "x86_64" {
    // x86-specific detection logic
} else if sysInfo.Architecture == "aarch64" {
    // ARM-specific detection logic
}

// Add to detection metadata
detection.Data = append(detection.Data,
    v1beta1.NewStringValue("system_arch", sysInfo.Architecture),
    v1beta1.NewStringValue("kernel_version", sysInfo.KernelRelease),
    v1beta1.NewStringValue("os", sysInfo.OSPrettyName))
```
{% endraw %}

---

## SyscallStore

### Interface

{% raw %}
```go
type SyscallStore interface {
    DataStore

    // GetSyscallName returns syscall name for given ID
    // Returns ErrNotFound if not found
    GetSyscallName(id int32) (string, error)

    // GetSyscallID returns syscall ID for given name
    // Returns ErrNotFound if not found
    GetSyscallID(name string) (int32, error)
}
```
{% endraw %}

### Methods

#### GetSyscallName

Get syscall name from syscall ID.

**Signature**:
{% raw %}
```go
GetSyscallName(id int32) (string, error)
```
{% endraw %}

**Parameters**:

- `id`: Syscall ID (architecture-specific)

**Returns**:

- `string`: Syscall name if found
- `error`: `ErrNotFound` if not found, `nil` on success

**Example**:
{% raw %}
```go
syscallID, found := v1beta1.GetData[int32](event, "syscall_id")
if !found {
    return nil, nil
}

name, err := d.dataStores.Syscalls().GetSyscallName(syscallID)
if errors.Is(err, datastores.ErrNotFound) {
    d.logger.Debugw("Unknown syscall", "id", syscallID)
    name = fmt.Sprintf("syscall_%d", syscallID)
}
if err != nil && !errors.Is(err, datastores.ErrNotFound) {
    return nil, fmt.Errorf("failed to get syscall name: %w", err)
}

d.logger.Infow("Syscall detected", "name", name, "id", syscallID)
```
{% endraw %}

#### GetSyscallID

Get syscall ID from syscall name.

**Signature**:
{% raw %}
```go
GetSyscallID(name string) (int32, error)
```
{% endraw %}

**Parameters**:

- `name`: Syscall name (e.g., "execve", "openat")

**Returns**:

- `int32`: Syscall ID if found
- `error`: `ErrNotFound` if not found, `nil` on success

**Example**:
{% raw %}
```go
id, err := d.dataStores.Syscalls().GetSyscallID("execve")
if err == nil {
    d.logger.Infow("Syscall", "name", "execve", "id", id)
    // ID = 59 on x86_64
}
```
{% endraw %}

!!! Warning "Architecture-Specific"
    Syscall IDs are **architecture-specific**:

    - ID 59 = `execve` on x86_64
    - ID 221 = `execve` on ARM64

    The store returns IDs for the **current architecture** only.

---

## KernelSymbolStore

### Interface

{% raw %}
```go
type KernelSymbolStore interface {
    DataStore

    // ResolveSymbolByAddress resolves address to symbols
    // Returns multiple symbols if aliases exist
    // Returns ErrNotFound if address cannot be resolved
    ResolveSymbolByAddress(addr uint64) ([]*SymbolInfo, error)

    // GetSymbolAddress returns address of named symbol
    // If multiple symbols exist, returns first one found
    // Returns ErrNotFound if symbol not found
    GetSymbolAddress(name string) (uint64, error)

    // ResolveSymbolsBatch resolves multiple addresses at once
    // Returns map of address -> symbols for found addresses
    // Missing addresses are not included in result
    ResolveSymbolsBatch(addrs []uint64) (map[uint64][]*SymbolInfo, error)
}
```
{% endraw %}

### SymbolInfo Structure

{% raw %}
```go
type SymbolInfo struct {
    Name    string // Symbol name: "do_sys_open"
    Address uint64 // Symbol address: 0xffffffff81234567
    Module  string // Module name: "system" for kernel, or module name
}
```
{% endraw %}

### Methods

#### ResolveSymbolByAddress

Resolve kernel address to symbol information.

**Signature**:
{% raw %}
```go
ResolveSymbolByAddress(addr uint64) ([]*SymbolInfo, error)
```
{% endraw %}

**Parameters**:

- `addr`: Kernel address to resolve

**Returns**:

- `[]*SymbolInfo`: List of symbols at this address (usually one, but aliases possible)
- `error`: `ErrNotFound` if address cannot be resolved

**Example**:
{% raw %}
```go
address, found := v1beta1.GetData[uint64](event, "address")
if !found {
    return nil, nil
}

symbols, err := d.dataStores.KernelSymbols().ResolveSymbolByAddress(address)
if errors.Is(err, datastores.ErrNotFound) {
    d.logger.Warnw("Unknown address", "addr", fmt.Sprintf("0x%x", address))
    return nil, nil
}
if err != nil {
    return nil, err
}

for _, symbol := range symbols {
    d.logger.Infow("Symbol",
        "name", symbol.Name,
        "address", fmt.Sprintf("0x%x", symbol.Address),
        "module", symbol.Module)

    // Check if this is a kernel module (rootkit detection)
    if symbol.Module != "system" {
        // Potential hook detected
        return []detection.DetectorOutput{{
            Data: []*v1beta1.EventValue{
                v1beta1.NewStringValue("symbol", symbol.Name),
                v1beta1.NewStringValue("module", symbol.Module),
            },
        }}, nil
    }
}
```
{% endraw %}

#### GetSymbolAddress

Get the address of a named kernel symbol.

**Signature**:
{% raw %}
```go
GetSymbolAddress(name string) (uint64, error)
```
{% endraw %}

**Parameters**:

- `name`: Symbol name (e.g., "do_sys_open")

**Returns**:

- `uint64`: Symbol address
- `error`: `ErrNotFound` if symbol not found

**Example**:
{% raw %}
```go
addr, err := d.dataStores.KernelSymbols().GetSymbolAddress("do_sys_open")
if errors.Is(err, datastores.ErrNotFound) {
    d.logger.Warnw("Symbol not found", "name", "do_sys_open")
    return nil, nil
}
if err != nil {
    return nil, err
}

d.logger.Infow("Symbol address",
    "name", "do_sys_open",
    "address", fmt.Sprintf("0x%x", addr))
```
{% endraw %}

#### ResolveSymbolsBatch

Resolve multiple addresses in a single call (more efficient).

**Signature**:
{% raw %}
```go
ResolveSymbolsBatch(addrs []uint64) (map[uint64][]*SymbolInfo, error)
```
{% endraw %}

**Parameters**:

- `addrs`: List of addresses to resolve

**Returns**:

- `map[uint64][]*SymbolInfo`: Map of address to symbols (only includes found addresses)
- `error`: Error if batch operation fails

**Example**:
{% raw %}
```go
// Get syscall table addresses from event
addresses := []uint64{0xffffffff81234567, 0xffffffff81abcdef, ...}

// Batch resolve (more efficient than individual lookups)
symbols, err := d.dataStores.KernelSymbols().ResolveSymbolsBatch(addresses)
if err != nil {
    return nil, err
}

// Process results
for addr, symbolList := range symbols {
    for _, symbol := range symbolList {
        d.logger.Infow("Resolved",
            "address", fmt.Sprintf("0x%x", addr),
            "symbol", symbol.Name,
            "module", symbol.Module)

        // Detect hooks by checking module
        if symbol.Module != "system" {
            // Hook detected
        }
    }
}

// Check for addresses that couldn't be resolved
for _, addr := range addresses {
    if _, found := symbols[addr]; !found {
        d.logger.Warnw("Address not resolved", "addr", fmt.Sprintf("0x%x", addr))
    }
}
```
{% endraw %}

---

## DNSStore

### Interface

{% raw %}
```go
type DNSStore interface {
    DataStore

    // GetDNSResponse retrieves cached DNS response
    // Returns ErrNotFound if no cached response found
    GetDNSResponse(query string) (*DNSResponse, error)
}
```
{% endraw %}

### DNSResponse Structure

{% raw %}
```go
type DNSResponse struct {
    Query   string   // DNS query (domain name)
    IPs     []string // Resolved IP addresses
    Domains []string // Resolved domains (for reverse lookups)
}
```
{% endraw %}

### Methods

#### GetDNSResponse

Retrieve cached DNS query response.

**Signature**:
{% raw %}
```go
GetDNSResponse(query string) (*DNSResponse, error)
```
{% endraw %}

**Parameters**:

- `query`: DNS query (domain name)

**Returns**:

- `*DNSResponse`: DNS response if cached
- `error`: `ErrNotFound` if not cached, `nil` on success

**Example**:
{% raw %}
```go
domain := "malicious.example.com"
response, err := d.dataStores.DNS().GetDNSResponse(domain)
if errors.Is(err, datastores.ErrNotFound) {
    d.logger.Debugw("No DNS cache entry", "domain", domain)
    return nil, nil
}
if err != nil {
    return nil, fmt.Errorf("failed to query DNS cache: %w", err)
}

d.logger.Infow("DNS cache hit",
    "domain", domain,
    "ips", response.IPs,
    "resolved_domains", response.Domains)
```
{% endraw %}

!!! Note "Cache Scope"
    The DNS cache only contains queries observed by Tracee while running.
    It does **not** contain historical or system-wide DNS data.

---

## Health and Metrics

### Health Information

All datastores expose health status:

{% raw %}
```go
type HealthInfo struct {
    Status    HealthStatus // Current health status
    Message   string       // Empty if healthy, error details if not
    LastCheck time.Time    // When health was last checked
}
```
{% endraw %}

**Example**:
{% raw %}
```go
processStore := d.dataStores.Processes()
health := processStore.GetHealth()

if health.Status != datastores.HealthHealthy {
    d.logger.Warnw("Process store unhealthy",
        "status", health.Status.String(),
        "message", health.Message,
        "last_check", health.LastCheck)

    // Decide whether to continue or fail
    if health.Status == datastores.HealthUnhealthy {
        return nil, fmt.Errorf("process store unhealthy: %s", health.Message)
    }
}
```
{% endraw %}

### Metrics

Datastores expose operational metrics:

{% raw %}
```go
type DataStoreMetrics struct {
    ItemCount    int64     // Number of items in store
    SuccessCount uint64    // Successful requests
    ErrorCount   uint64    // Failed requests
    CacheHits    uint64    // Cache hits (if applicable)
    CacheMisses  uint64    // Cache misses (if applicable)
    LastAccess   time.Time // Last access time
}
```
{% endraw %}

**Example**:
{% raw %}
```go
processStore := d.dataStores.Processes()
metrics := processStore.GetMetrics()

d.logger.Infow("Process store metrics",
    "item_count", metrics.ItemCount,
    "success_count", metrics.SuccessCount,
    "error_count", metrics.ErrorCount,
    "cache_hits", metrics.CacheHits,
    "cache_misses", metrics.CacheMisses,
    "hit_rate", float64(metrics.CacheHits) / float64(metrics.CacheHits + metrics.CacheMisses),
    "last_access", metrics.LastAccess)

// Alert if error rate is high
if metrics.ErrorCount > 0 {
    errorRate := float64(metrics.ErrorCount) / float64(metrics.SuccessCount + metrics.ErrorCount)
    if errorRate > 0.01 {
        d.logger.Warnw("High error rate", "rate", errorRate)
    }
}
```
{% endraw %}

---

## Error Handling

### Error Classification

**Not Found (common, non-error)**:
{% raw %}
```go
proc, err := d.dataStores.Processes().GetProcess(entityId)
if errors.Is(err, datastores.ErrNotFound) {
    // Process not in tree (maybe exited) - this is normal
    d.logger.Debugw("Process not found", "entity_id", entityId)
    return nil, nil  // Skip gracefully
}
```
{% endraw %}

**Store Errors (critical)**:
{% raw %}
```go
symbols, err := d.dataStores.KernelSymbols().ResolveSymbolByAddress(addr)
if err != nil {
    // Check for specific error types
    if errors.Is(err, datastores.ErrNotFound) {
        d.logger.Warnw("Address not in symbol table", "addr", addr)
        return nil, nil  // Skip gracefully
    }

    if errors.Is(err, datastores.ErrStoreUnhealthy) {
        // Store is unhealthy - critical
        return nil, fmt.Errorf("symbol store unhealthy: %w", err)
    }

    // Other error - log and return
    return nil, fmt.Errorf("symbol resolution failed: %w", err)
}
```
{% endraw %}

### Graceful Degradation

Always handle missing/unavailable stores gracefully:

{% raw %}
```go
func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
    // Check if optional store is available (use IsAvailable for readiness check)
    if d.dataStores.IsAvailable("system") {
        systemStore := d.dataStores.System()
        sysInfo := systemStore.GetSystemInfo()
        // Use system info for enrichment
    } else {
        d.logger.Debugw("System store unavailable, continuing without system info")
        // Continue detection without system info
    }

    // Check for optional data
    container, err := d.dataStores.Containers().GetContainer(containerID)
    if errors.Is(err, datastores.ErrNotFound) {
        d.logger.Debugw("Container not found, continuing without container context")
        // Continue detection without container info
    } else if err != nil {
        return nil, fmt.Errorf("container store error: %w", err)
    } else {
        // Use container info for enrichment
    }

    // Core detection logic...
}
```
{% endraw %}

---

## Advanced Usage

### Combining Multiple Stores

{% raw %}
```go
func (d *ContainerEscapeDetector) analyzeEscape(event *v1beta1.Event) ([]detection.DetectorOutput, error) {
    // Get process information
    entityId := event.Workload.Process.EntityId.Value
    proc, err := d.dataStores.Processes().GetProcess(entityId)
    if errors.Is(err, datastores.ErrNotFound) {
        return nil, nil
    }
    if err != nil {
        return nil, fmt.Errorf("process store error: %w", err)
    }

    // Get process ancestry
    ancestry, err := d.dataStores.Processes().GetAncestry(entityId, 5)
    if err != nil {
        return nil, err
    }

    // Get container information
    containerID := v1beta1.GetContainerID(event)
    container, err := d.dataStores.Containers().GetContainer(containerID)
    if errors.Is(err, datastores.ErrNotFound) {
        return nil, nil
    }
    if err != nil {
        return nil, fmt.Errorf("container store error: %w", err)
    }

    // Get system information
    sysInfo := d.dataStores.System().GetSystemInfo()

    // Analyze all together
    if d.detectEscape(proc, ancestry, container, sysInfo) {
        return []detection.DetectorOutput{{
            Data: []*v1beta1.EventValue{
                v1beta1.NewStringValue("process", proc.Exe),
                v1beta1.NewStringValue("container", container.Name),
                v1beta1.NewStringValue("kernel", sysInfo.KernelRelease),
            },
        }}, nil
    }

    return nil, nil
}
```
{% endraw %}

### Caching Store References

Cache store references in Init() for better performance:

{% raw %}
```go
type MyDetector struct {
    logger         detection.Logger
    processStore   datastores.ProcessStore
    containerStore datastores.ContainerStore
    systemStore    datastores.SystemStore
}

func (d *MyDetector) Init(params detection.DetectorParams) error {
    d.logger = params.Logger

    // Cache store references (registry always returns non-nil stores)
    d.processStore = params.DataStores.Processes()
    d.containerStore = params.DataStores.Containers()
    d.systemStore = params.DataStores.System()

    // Validate required stores are available
    if !params.DataStores.IsAvailable("process") {
        return fmt.Errorf("process store required but not available")
    }

    // Warn about optional stores
    if !params.DataStores.IsAvailable("system") {
        d.logger.Warnw("System store unavailable, some features disabled")
    }

    return nil
}

func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
    // Use cached references (no registry lookup)
    proc, err := d.processStore.GetProcess(entityId)
    if errors.Is(err, datastores.ErrNotFound) {
        return nil, nil
    }

    container, err := d.containerStore.GetContainer(containerID)
    if errors.Is(err, datastores.ErrNotFound) {
        return nil, nil
    }

    // System store always available (cached reference)
    sysInfo := d.systemStore.GetSystemInfo()
    // Use system info

    // ...
}
```
{% endraw %}

---

## Writable DataStores

### Overview

Writable datastores allow detectors and extensions to store and share custom data. Unlike read-only stores (which are populated by Tracee), writable stores can be written to by:
- **Detectors** that need to maintain correlation state
- **Extensions** that feed external threat intelligence
- **External clients** via gRPC API (future feature)

**Key Features:**
- **Type-safe**: Protobuf schemas for keys and data
- **Source isolation**: Multiple data sources can coexist
- **Ownership model**: Registrant controls write access and defines store behavior

### Registering a Writable Store

Detectors register writable stores in their `Init()` method:

```go
import (
    "github.com/aquasecurity/tracee/api/v1beta1/detection"
    "github.com/aquasecurity/tracee/api/v1beta1/datastores"
    "github.com/aquasecurity/tracee/pkg/datastores/ipreputation"
)

type CorrelationDetector struct {
    logger         detection.Logger
    correlationStore datastores.WritableStore  // Owner keeps WritableStore interface
}

func (d *CorrelationDetector) Init(params detection.DetectorParams) error {
    d.logger = params.Logger

    // Create a writable store
    // Store-specific configuration (like conflict resolution) is defined here
    store := ipreputation.NewIPReputationStore(
        ipreputation.LastWriteWins,  // Store-specific policy
        nil,                          // Store-specific options
    )

    // Register via registry - caller becomes owner
    if err := params.DataStores.RegisterWritableStore("ip_reputation", store); err != nil {
        return fmt.Errorf("failed to register store: %w", err)
    }

    // Keep reference for writing
    d.correlationStore = store
    d.logger.Infow("Registered IP reputation store")
    return nil
}
```

**Key Points:**
- The registrant owns the store and defines its behavior (e.g., conflict resolution policies)
- Store name must be unique across the system
- Registration should happen in `Init()` before any event processing

### Writing to a Writable Store

**Type-Safe Method (Internal Go Code):**

```go
func (d *CorrelationDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]*v1beta1.Event, error) {
    // Owner can write using type-safe methods
    ipStore := d.correlationStore.(*ipreputation.IPReputationStore)

    srcIP, found := v1beta1.GetData[string](event, "src_ip")
    if !found {
        return nil, nil
    }

    rep := &ipreputation.IPReputation{
        Status:      ipreputation.ReputationBlacklisted,
        Severity:    8,
        Tags:        []string{"detected_by_tracee"},
        LastUpdated: time.Now(),
    }

    if err := ipStore.WriteReputation("local_detector", srcIP, rep); err != nil {
        d.logger.Errorw("Failed to write reputation", "error", err)
    }

    return nil, nil
}
```

**Protobuf Method (gRPC or Generic):**

```go
import (
    pb "github.com/aquasecurity/tracee/api/v1beta1/datastores"
    "google.golang.org/protobuf/types/known/anypb"
    "google.golang.org/protobuf/types/known/timestamppb"
)

func (d *CorrelationDetector) writeViaProtobuf(ip string) error {
    // Create protobuf messages
    keyMsg := &pb.IPAddressKey{Ip: ip}
    repMsg := &pb.IPReputation{
        Status:      pb.ReputationStatus_REPUTATION_BLACKLISTED,
        Severity:    8,
        Tags:        []string{"malware"},
        LastUpdated: timestamppb.Now(),
    }

    // Pack into Any
    keyAny, _ := anypb.New(keyMsg)
    dataAny, _ := anypb.New(repMsg)

    // Write via generic interface
    entry := &datastores.DataEntry{
        Key:  keyAny,
        Data: dataAny,
    }

    return d.correlationStore.WriteValue("detector_source", entry)
}
```

### Reading from a Writable Store

Other detectors can read from writable stores (read-only access):

```go
type ThreatAnalyzer struct {
    logger     detection.Logger
    ipRepStore *ipreputation.IPReputationStore  // Read-only access
}

func (d *ThreatAnalyzer) Init(params detection.DetectorParams) error {
    d.logger = params.Logger

    // Access as DataStore (read-only)
    store, err := params.DataStores.GetCustom("ip_reputation")
    if err != nil {
        d.logger.Warnw("IP reputation store not available, degrading gracefully")
        return nil  // Optional dependency
    }

    // Type assert to access read methods
    d.ipRepStore = store.(*ipreputation.IPReputationStore)
    return nil
}

func (d *ThreatAnalyzer) OnEvent(ctx context.Context, event *v1beta1.Event) ([]*v1beta1.Event, error) {
    if d.ipRepStore == nil {
        return nil, nil  // Store not available
    }

    srcIP, found := v1beta1.GetData[string](event, "src_ip")
    if !found {
        return nil, nil
    }

    // Check if IP is blacklisted
    if d.ipRepStore.IsBlacklisted(srcIP) {
        d.logger.Warnw("Connection from blacklisted IP", "ip", srcIP)
        return d.createThreatDetection(event), nil
    }

    return nil, nil
}
```

### Source Isolation

The `WritableStore` API includes a `source` parameter to organize data by origin:

```go
// Generic WritableStore methods all accept a source parameter
store.WriteValue("external_feed", entry)
store.WriteValue("local_detector", entry)
store.Delete("external_feed", key)
store.ClearSource("external_feed")  // Remove all data from this source
sources, _ := store.ListSources()   // ["external_feed", "local_detector"]
```

**Purpose:**
- Track data provenance (which feed/detector provided this data)
- Support independent updates (each source can update without affecting others)
- Enable cleanup by source (remove all data from a specific feed)

**Implementation Note:** How multiple sources writing to the same key are handled (conflict resolution) is implementation-specific and defined by the store owner when creating the store.

### Batch Operations

For performance, use batch writes when available:

```go
// Using the generic WritableStore interface
entries := []*datastores.DataEntry{
    {Key: keyAny1, Data: dataAny1},
    {Key: keyAny2, Data: dataAny2},
    {Key: keyAny3, Data: dataAny3},
}

if err := store.WriteBatchValues("bulk_import", entries); err != nil {
    return fmt.Errorf("batch write failed: %w", err)
}
```

**Implementation-Specific Note:** Some stores may provide type-safe batch methods in addition to the generic interface. Consult the specific store's documentation (e.g., `pkg/datastores/ipreputation/`) for details.

### Example: IP Reputation Detector

This example shows a complete detector using a writable store. Note that the IP Reputation Store (`pkg/datastores/ipreputation/`) is a reference implementation with additional type-safe methods beyond the generic `WritableStore` interface.

```go
package detectors

import (
    "context"
    "time"

    "github.com/aquasecurity/tracee/api/v1beta1"
    "github.com/aquasecurity/tracee/api/v1beta1/detection"
    "github.com/aquasecurity/tracee/pkg/datastores/ipreputation"
)

func init() {
    register(&IPReputationDetector{})
}

type IPReputationDetector struct {
    logger   detection.Logger
    ipStore  *ipreputation.IPReputationStore
}

func (d *IPReputationDetector) GetDefinition() detection.DetectorDefinition {
    return detection.DetectorDefinition{
        ID: "TRC-IP-001",
        Requirements: detection.DetectorRequirements{
            Events: []detection.EventRequirement{
                {Name: "net_packet_tcp"},
                {Name: "security_socket_connect"},
            },
        },
        ProducedEvent: v1beta1.EventDefinition{
            Name:        "malicious_ip_connection",
            Description: "Connection to known malicious IP address",
            Version:     &v1beta1.Version{Major: 1},
        },
        ThreatMetadata: &v1beta1.Threat{
            Name:     "Malicious IP Connection",
            Severity: v1beta1.Severity_HIGH,
        },
        AutoPopulate: detection.AutoPopulateFields{
            Threat:       true,
            DetectedFrom: true,
        },
    }
}

func (d *IPReputationDetector) Init(params detection.DetectorParams) error {
    d.logger = params.Logger

    // Register IP reputation store
    store := ipreputation.NewIPReputationStore(
        ipreputation.MaxSeverity,  // Highest severity wins
        map[string]int{
            "local_detector": 10,
            "external_feed":  5,
        },
    )

    if err := params.DataStores.RegisterWritableStore("ip_reputation", store); err != nil {
        return err
    }

    d.ipStore = store
    d.logger.Infow("IP reputation detector initialized")
    return nil
}

func (d *IPReputationDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]*v1beta1.Event, error) {
    // Extract destination IP
    destIP, found := v1beta1.GetData[string](event, "dst_ip")
    if !found {
        return nil, nil
    }

    // Check reputation
    if d.ipStore.IsBlacklisted(destIP) {
        rep, _ := d.ipStore.GetReputation(destIP)

        // Create detection event
        detection := v1beta1.CreateEventFromBase(event)
        detection.Data = []*v1beta1.EventValue{
            v1beta1.NewStringValue("malicious_ip", destIP),
            v1beta1.NewInt32Value("severity", int32(rep.Severity)),
            v1beta1.NewStringValue("tags", strings.Join(rep.Tags, ",")),
        }

        return []*v1beta1.Event{detection}, nil
    }

    // Learn from observed connections (update store)
    if isSuspiciousBehavior(event) {
        rep := &ipreputation.IPReputation{
            IP:          destIP,
            Status:      ipreputation.ReputationSuspicious,
            Severity:    5,
            Tags:        []string{"suspicious_behavior"},
            LastUpdated: time.Now(),
        }
        d.ipStore.WriteReputation("local_detector", destIP, rep)
    }

    return nil, nil
}
```

### Ownership and Access Control

**Ownership Model:**
- The entity that calls `RegisterWritableStore()` owns the store
- Owner keeps the `WritableStore` interface reference for writing
- Other consumers access via `GetCustom()` as `DataStore` (read-only)
- No authorization logic needed - access control is implicit via interface typing

**Benefits:**
- **Simple implementation**: No permission checks in store code
- **Type-safe**: WritableStore methods only available to owner
- **Clear responsibility**: Owner defines conflict resolution and retention policies
- **Flexible sharing**: Multiple detectors can read, only owner writes

---

## Summary

### Quick Reference

| Store | Primary Use | Key Methods |
|-------|-------------|-------------|
| **ProcessStore** | Process info & ancestry | `GetProcess()`, `GetAncestry()`, `GetChildProcesses()` |
| **ContainerStore** | Container metadata | `GetContainer()`, `GetContainerByName()` |
| **SystemStore** | System information | `GetSystemInfo()` |
| **SyscallStore** | Syscall ID/name mapping | `GetSyscallName()`, `GetSyscallID()` |
| **KernelSymbolStore** | Symbol resolution | `ResolveSymbolByAddress()`, `ResolveSymbolsBatch()` |
| **DNSStore** | DNS cache | `GetDNSResponse()` |

### Best Practices

1. **Use EntityID, not PID** for process lookups
2. **Cache store references** in Init() for performance
3. **Handle missing data gracefully** (stores may be unavailable)
4. **Use batch operations** when resolving multiple items
5. **Check health status** before critical operations
6. **Monitor metrics** for performance insights
7. **Fail fast** on critical errors, degrade gracefully on optional failures

### Next Steps

- Read the [Detector API Reference](api-reference.md) for complete detector development
- Start with the [Quick Start Guide](quickstart.md) to write your first detector
- Study real detector implementations in `detectors/` directory

---

**API Version**: v1beta1
**Last Updated**: From implementation commits (60 commits analyzing detector and datastore system)
