package ipreputation

import (
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// IPReputationStore provides IP reputation lookup with conflict resolution
type IPReputationStore interface {
	datastores.WritableStore

	// Type-safe write methods for internal Go usage
	WriteReputation(source string, ip string, rep *IPReputation) error
	WriteBatch(source string, data map[string]*IPReputation) error

	// Query operations
	GetReputation(ip string) (*IPReputation, bool)
	IsBlacklisted(ip string) bool
	IsWhitelisted(ip string) bool
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

func (s *store) Name() string {
	return "ip_reputation"
}

func (s *store) GetHealth() *datastores.HealthInfo {
	return &datastores.HealthInfo{
		Status:    datastores.HealthHealthy,
		Message:   "",
		LastCheck: time.Now(),
	}
}

func (s *store) GetMetrics() *datastores.DataStoreMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()

	totalCount := int64(0)
	for _, sourceData := range s.data {
		totalCount += int64(len(sourceData))
	}

	return &datastores.DataStoreMetrics{
		ItemCount:  totalCount,
		LastAccess: time.Unix(0, s.lastAccessNano),
	}
}

// WritableStore interface implementation

func (s *store) WriteValue(source string, entry *datastores.DataEntry) error {
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

	// Validate severity
	if rep.Severity < 1 || rep.Severity > 10 {
		return fmt.Errorf("severity must be 1-10, got %d", rep.Severity)
	}

	return s.WriteReputation(source, keyMsg.Ip, rep)
}

func (s *store) WriteBatchValues(source string, entries []*datastores.DataEntry) error {
	batch := make(map[string]*IPReputation, len(entries))

	// Parse all entries first (fail fast if any are invalid)
	for i, entry := range entries {
		var keyMsg datastores.IPAddressKey
		if err := entry.Key.UnmarshalTo(&keyMsg); err != nil {
			return fmt.Errorf("entry %d: invalid key type (expected IPAddressKey): %w", i, err)
		}

		var repMsg datastores.IPReputation
		if err := entry.Data.UnmarshalTo(&repMsg); err != nil {
			return fmt.Errorf("entry %d: invalid data type (expected IPReputation): %w", i, err)
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

		if rep.Severity < 1 || rep.Severity > 10 {
			return fmt.Errorf("entry %d: severity must be 1-10, got %d", i, rep.Severity)
		}

		batch[keyMsg.Ip] = rep
	}

	// All entries valid, write them
	return s.WriteBatch(source, batch)
}

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

func (s *store) ClearSource(source string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.data, source)
	return nil
}

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

func (s *store) WriteReputation(source string, ip string, rep *IPReputation) error {
	if rep.Severity < 1 || rep.Severity > 10 {
		return fmt.Errorf("severity must be 1-10, got %d", rep.Severity)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.data[source] == nil {
		s.data[source] = make(map[string]*IPReputation)
	}

	// Update source field to match the key
	rep.Source = source
	s.data[source][ip] = rep
	s.lastAccessNano = time.Now().UnixNano()

	return nil
}

func (s *store) WriteBatch(source string, data map[string]*IPReputation) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.data[source] == nil {
		s.data[source] = make(map[string]*IPReputation)
	}

	for ip, rep := range data {
		if rep.Severity < 1 || rep.Severity > 10 {
			return fmt.Errorf("severity must be 1-10 for IP %s, got %d", ip, rep.Severity)
		}
		rep.Source = source
		s.data[source][ip] = rep
	}

	s.lastAccessNano = time.Now().UnixNano()
	return nil
}

// Query operations

func (s *store) GetReputation(ip string) (*IPReputation, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result *IPReputation
	for source, sourceData := range s.data {
		if rep, ok := sourceData[ip]; ok {
			result = s.resolveConflict(result, rep, source)
		}
	}

	return result, result != nil
}

func (s *store) IsBlacklisted(ip string) bool {
	rep, found := s.GetReputation(ip)
	return found && rep.Status == ReputationBlacklisted
}

func (s *store) IsWhitelisted(ip string) bool {
	rep, found := s.GetReputation(ip)
	return found && rep.Status == ReputationWhitelisted
}

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
	case LastWriteWins:
		if incoming.LastUpdated.After(existing.LastUpdated) {
			return incoming
		}
		return existing

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
