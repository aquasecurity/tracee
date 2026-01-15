package detection

// Enrichment names for use in EnrichmentRequirement
const (
	EnrichmentEnvironment    = "environment"     // Capture exec environment variables
	EnrichmentExecutableHash = "executable-hash" // Calculate executable hashes
	EnrichmentContainer      = "container"       // Enrich container metadata fields
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
