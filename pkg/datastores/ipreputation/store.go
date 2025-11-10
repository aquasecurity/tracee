package ipreputation

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// IPReputationStore provides IP reputation lookup with conflict resolution
type IPReputationStore interface {
	datastores.WritableStore

	// Type-safe write methods for internal Go usage
	WriteReputation(source string, ip string, rep *IPReputation) error
	WriteReputationBatch(source string, data map[string]*IPReputation) error

	// Query operations
	GetReputation(ip string) (*IPReputation, bool)
	IsDenied(ip string) bool
	IsAllowed(ip string) bool
	CheckIPs(ips []string) map[string]*IPReputation
}

// store implements IPReputationStore
type store struct {
	// data is organized as [source][ip] = reputation
	data           map[string]map[string]*IPReputation
	conflictPolicy ConflictResolutionPolicy
	sourcePriority map[string]int
	mu             sync.RWMutex
	lastAccessNano int64
}

// NewIPReputationStore creates a new IP reputation store
func NewIPReputationStore(policy ConflictResolutionPolicy, sourcePriority map[string]int) IPReputationStore {
	if sourcePriority == nil {
		sourcePriority = make(map[string]int)
	}
	return &store{
		data:           make(map[string]map[string]*IPReputation),
		conflictPolicy: policy,
		sourcePriority: sourcePriority,
	}
}

// DataStore interface implementation

// Name returns the datastore identifier
func (s *store) Name() string {
	return "ip_reputation"
}

// GetHealth returns the current health status of the datastore
func (s *store) GetHealth() *datastores.HealthInfo {
	return &datastores.HealthInfo{
		Status:    datastores.HealthHealthy,
		Message:   "",
		LastCheck: time.Now(),
	}
}

// GetMetrics returns operational metrics including total item count and last access time
func (s *store) GetMetrics() *datastores.DataStoreMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()

	totalCount := int64(0)
	for _, sourceData := range s.data {
		totalCount += int64(len(sourceData))
	}

	return &datastores.DataStoreMetrics{
		ItemCount:  totalCount,
		LastAccess: time.Unix(0, atomic.LoadInt64(&s.lastAccessNano)),
	}
}

// WritableStore interface implementation

// validateReputation validates reputation data
func validateReputation(rep *IPReputation) error {
	if rep.Severity < 1 || rep.Severity > 10 {
		return fmt.Errorf("severity must be 1-10, got %d", rep.Severity)
	}
	// Validate status enum range (protobuf enum values)
	if rep.Status < ReputationUnknown || rep.Status > ReputationSuspicious {
		return fmt.Errorf("invalid reputation status: %d", rep.Status)
	}
	return nil
}

// Write writes a single IP reputation entry from protobuf format
// Unpacks and validates the protobuf DataEntry before delegating to WriteReputation
func (s *store) Write(source string, entry *datastores.DataEntry) error {
	// Unpack key
	var keyMsg datastores.IPAddressKey
	if err := entry.Key.UnmarshalTo(&keyMsg); err != nil {
		return fmt.Errorf("invalid key type (expected IPAddressKey): %w", err)
	}

	// Unpack data
	var repMsg datastores.IPReputation
	if err := entry.Data.UnmarshalTo(&repMsg); err != nil {
		return fmt.Errorf("invalid data type (expected IPReputation): %w", err)
	}

	// Validate status enum from protobuf
	if repMsg.Status < 0 || repMsg.Status > 3 {
		return fmt.Errorf("invalid reputation status: %d", repMsg.Status)
	}

	// Convert protobuf to internal Go struct
	rep := &IPReputation{
		IP:          keyMsg.Ip,
		Status:      ReputationStatus(repMsg.Status),
		Source:      source,
		Severity:    int(repMsg.Severity),
		Tags:        repMsg.Tags,
		LastUpdated: repMsg.LastUpdated.AsTime(),
		Metadata:    repMsg.Metadata,
	}

	// Validate reputation data
	if err := validateReputation(rep); err != nil {
		return err
	}

	return s.WriteReputation(source, keyMsg.Ip, rep)
}

// WriteBatch writes multiple IP reputation entries from protobuf format
// All entries are validated before writing (atomic operation - all succeed or all fail)
func (s *store) WriteBatch(source string, entries []*datastores.DataEntry) error {
	batch := make(map[string]*IPReputation, len(entries))

	// Parse and validate all entries first (fail fast if any are invalid)
	for i, entry := range entries {
		var keyMsg datastores.IPAddressKey
		if err := entry.Key.UnmarshalTo(&keyMsg); err != nil {
			return fmt.Errorf("entry %d: invalid key type (expected IPAddressKey): %w", i, err)
		}

		var repMsg datastores.IPReputation
		if err := entry.Data.UnmarshalTo(&repMsg); err != nil {
			return fmt.Errorf("entry %d: invalid data type (expected IPReputation): %w", i, err)
		}

		// Validate status enum from protobuf
		if repMsg.Status < 0 || repMsg.Status > 3 {
			return fmt.Errorf("entry %d: invalid reputation status: %d", i, repMsg.Status)
		}

		rep := &IPReputation{
			IP:          keyMsg.Ip,
			Status:      ReputationStatus(repMsg.Status),
			Source:      source,
			Severity:    int(repMsg.Severity),
			Tags:        repMsg.Tags,
			LastUpdated: repMsg.LastUpdated.AsTime(),
			Metadata:    repMsg.Metadata,
		}

		// Validate before adding to batch
		if err := validateReputation(rep); err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}

		batch[keyMsg.Ip] = rep
	}

	// All entries valid, write them atomically
	return s.WriteReputationBatch(source, batch)
}

// Delete removes a specific IP address entry from a source
// Returns nil if the key doesn't exist (idempotent)
func (s *store) Delete(source string, key *anypb.Any) error {
	var keyMsg datastores.IPAddressKey
	if err := key.UnmarshalTo(&keyMsg); err != nil {
		return fmt.Errorf("invalid key type (expected IPAddressKey): %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if sourceData, ok := s.data[source]; ok {
		delete(sourceData, keyMsg.Ip)
		if len(sourceData) == 0 {
			delete(s.data, source)
		}
	}

	return nil
}

// Clear removes all IP reputation data from a specific source
// Returns nil if the source doesn't exist (idempotent)
func (s *store) Clear(source string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.data, source)
	return nil
}

// ListSources returns all source identifiers that have data in this store
func (s *store) ListSources() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sources := make([]string, 0, len(s.data))
	for source := range s.data {
		sources = append(sources, source)
	}

	return sources, nil
}

// Type-safe methods for internal Go usage

// WriteReputation writes a single IP reputation entry using native Go types
// Validates the reputation data before writing
func (s *store) WriteReputation(source string, ip string, rep *IPReputation) error {
	// Validate before acquiring lock
	if err := validateReputation(rep); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.data[source] == nil {
		s.data[source] = make(map[string]*IPReputation)
	}

	// Update source field to match the key
	rep.Source = source
	s.data[source][ip] = rep
	atomic.StoreInt64(&s.lastAccessNano, time.Now().UnixNano())

	return nil
}

// WriteReputationBatch writes multiple IP reputation entries using native Go types
// All entries are validated before writing (atomic operation - all succeed or all fail)
func (s *store) WriteReputationBatch(source string, data map[string]*IPReputation) error {
	// Validate all entries before acquiring lock (atomic operation)
	for ip, rep := range data {
		if err := validateReputation(rep); err != nil {
			return fmt.Errorf("validation failed for IP %s: %w", ip, err)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.data[source] == nil {
		s.data[source] = make(map[string]*IPReputation)
	}

	for ip, rep := range data {
		rep.Source = source
		s.data[source][ip] = rep
	}

	atomic.StoreInt64(&s.lastAccessNano, time.Now().UnixNano())
	return nil
}

// Query operations

// GetReputation retrieves the aggregated reputation for an IP address
// If multiple sources have data for the same IP, applies the configured conflict resolution policy
func (s *store) GetReputation(ip string) (*IPReputation, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result *IPReputation
	for source, sourceData := range s.data {
		if rep, ok := sourceData[ip]; ok {
			result = s.resolveConflict(result, rep, source)
		}
	}

	// Update last access time atomically (no lock needed)
	if result != nil {
		atomic.StoreInt64(&s.lastAccessNano, time.Now().UnixNano())
	}

	return result, result != nil
}

// IsDenied checks if an IP address has a deny/block reputation status
func (s *store) IsDenied(ip string) bool {
	rep, found := s.GetReputation(ip)
	return found && rep.Status == ReputationDeny
}

// IsAllowed checks if an IP address has an allow/trusted reputation status
func (s *store) IsAllowed(ip string) bool {
	rep, found := s.GetReputation(ip)
	return found && rep.Status == ReputationAllow
}

// CheckIPs performs a batch reputation lookup for multiple IP addresses
// Returns a map containing only IPs that have reputation data
func (s *store) CheckIPs(ips []string) map[string]*IPReputation {
	result := make(map[string]*IPReputation, len(ips))
	for _, ip := range ips {
		if rep, found := s.GetReputation(ip); found {
			result[ip] = rep
		}
	}
	return result
}

// resolveConflict applies the conflict resolution policy when multiple sources have data for the same IP
func (s *store) resolveConflict(existing, incoming *IPReputation, incomingSource string) *IPReputation {
	if existing == nil {
		return incoming
	}

	switch s.conflictPolicy {
	case MaxSeverity:
		if incoming.Severity > existing.Severity {
			return incoming
		}
		return existing

	case PriorityBased:
		incomingPriority := s.sourcePriority[incomingSource]
		existingPriority := s.sourcePriority[existing.Source]
		if incomingPriority > existingPriority {
			return incoming
		}
		return existing

	default:
		// Default to LastWriteWins
		if incoming.LastUpdated.After(existing.LastUpdated) {
			return incoming
		}
		return existing
	}
}
