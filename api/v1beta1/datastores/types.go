package datastores

import "time"

// ProcessInfo contains information about a process
type ProcessInfo struct {
	EntityID  uint64    // Primary key (hash from ProcessTree) - matches Event.Process.EntityId
	PID       uint32    // OS process ID (for display/logging)
	PPID      uint32    // OS parent PID (for display/logging)
	Name      string    // Binary name only: "bash"
	Exe       string    // Full path: "/usr/bin/bash"
	StartTime time.Time // Process start time
	UID       uint32    // User ID
	GID       uint32    // Group ID
	// Phase 2: CmdLine/Args (memory impact)
}

// ContainerInfo contains information about a container
type ContainerInfo struct {
	ID          string      // Container ID
	Name        string      // Container name
	Image       string      // Container image
	ImageDigest string      // Image digest
	Runtime     string      // Runtime (docker, containerd, crio)
	StartTime   time.Time   // Container start time
	Pod         *K8sPodInfo // Kubernetes pod info (nil for non-K8s containers)
	// Phase 2: Labels (requires runtime extraction), Status, PID, Env, Mounts
}

// K8sPodInfo contains Kubernetes pod metadata
type K8sPodInfo struct {
	Name      string // Pod name
	UID       string // Pod UID
	Namespace string // Pod namespace
	Sandbox   bool   // Whether this is a sandbox container
}

// SymbolInfo contains information about a kernel symbol
type SymbolInfo struct {
	Name    string // Symbol name
	Address uint64 // Symbol address
	Module  string // Module name (or "system" for kernel symbols)
}

// DNSResponse contains DNS query response information
type DNSResponse struct {
	Query   string   // DNS query (domain name)
	IPs     []string // Resolved IP addresses
	Domains []string // Resolved domain names (for reverse lookups)
}

// HealthStatus represents the health state of a datastore
type HealthStatus int

const (
	HealthUnknown HealthStatus = iota
	HealthHealthy
	HealthUnhealthy
)

func (h HealthStatus) String() string {
	switch h {
	case HealthHealthy:
		return "healthy"
	case HealthUnhealthy:
		return "unhealthy"
	default:
		return "unknown"
	}
}

// HealthInfo contains health information about a datastore
type HealthInfo struct {
	Status    HealthStatus // Current health status
	Message   string       // Empty if healthy, error details if not
	LastCheck time.Time    // When health was last checked
}

// DataStoreMetrics contains metrics about datastore operations
type DataStoreMetrics struct {
	ItemCount    int64     // Number of items in store
	SuccessCount uint64    // Number of successful requests
	ErrorCount   uint64    // Number of failed requests
	CacheHits    uint64    // Number of cache hits (if applicable)
	CacheMisses  uint64    // Number of cache misses (if applicable)
	LastAccess   time.Time // Last access time
}

// DataStoreMetadata contains metadata about a datastore
type DataStoreMetadata struct {
	Name        string         // Human-readable name (e.g., "processes")
	Description string         // What this store provides
	Config      map[string]any // Store-specific configuration
}

// SystemInfo contains immutable system-level information collected at startup
type SystemInfo struct {
	Architecture    string            // CPU architecture (e.g., "x86_64", "aarch64")
	KernelRelease   string            // Kernel version (e.g., "5.15.0-generic")
	Hostname        string            // System hostname
	BootTime        time.Time         // System boot time
	TraceeStartTime time.Time         // Time when Tracee started
	OSName          string            // OS name (e.g., "Ubuntu")
	OSVersion       string            // OS version (e.g., "22.04")
	OSPrettyName    string            // Human-readable full OS name (e.g., "Ubuntu 22.04 LTS")
	TraceeVersion   string            // Tracee version string
	InitNamespaces  map[string]uint32 // Init process namespaces (cgroup, ipc, mnt, net, pid, etc.)
}
