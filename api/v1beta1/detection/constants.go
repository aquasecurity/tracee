package detection

// Enrichment names for use in EnrichmentRequirement
const (
	EnrichmentEnvironment    = "environment"     // Capture exec environment variables
	EnrichmentExecutableHash = "executable-hash" // Calculate executable hashes
	EnrichmentContainer      = "container"       // Enrich container metadata fields
)

// Executable hash config types for use in EnrichmentRequirement.Config
const (
	ExecutableHashConfigInode       = "inode"        // Recalculate hash if inode ctime differs
	ExecutableHashConfigDevInode    = "dev-inode"    // Key hash by device and inode pair
	ExecutableHashConfigDigestInode = "digest-inode" // Key hash by container image digest and inode
)

// DataStore names for use in DataStoreRequirement
const (
	DataStoreProcess   = "process"   // Process tree datastore
	DataStoreContainer = "container" // Container metadata datastore
	DataStoreSymbol    = "symbol"    // Symbol resolution datastore
	DataStoreDNS       = "dns"       // DNS query datastore
	DataStoreSystem    = "system"    // System information datastore
	DataStoreSyscall   = "syscall"   // Syscall information datastore
)
