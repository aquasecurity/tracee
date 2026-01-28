//go:build e2e

package e2e

import (
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	dsapi "github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// E2eWritableStoreName is the registry name for the e2e writable data store (used by E2eWritableStore detector).
const E2eWritableStoreName = "writable_store"

// e2eWritableStore is the writable data store implementation used by the E2eWritableStore detector.
// It implements dsapi.WritableStore and provides GetValue for the detector.
type e2eWritableStore struct {
	mu      sync.RWMutex
	data    map[string]string
	sources map[string]struct{}
}

// NewE2eWritableStore creates a new e2e writable data store implementation.
func NewE2eWritableStore() *e2eWritableStore {
	return &e2eWritableStore{
		data:    make(map[string]string),
		sources: make(map[string]struct{}),
	}
}

// GetValue returns the value for key. Used by the E2eWritableStore detector.
func (s *e2eWritableStore) GetValue(key string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[key]
	return v, ok
}

// Name implements dsapi.DataStore.
func (s *e2eWritableStore) Name() string { return E2eWritableStoreName }

// GetHealth implements dsapi.DataStore.
func (s *e2eWritableStore) GetHealth() *dsapi.HealthInfo {
	return &dsapi.HealthInfo{Status: dsapi.HealthHealthy, LastCheck: time.Now()}
}

// GetMetrics implements dsapi.DataStore.
func (s *e2eWritableStore) GetMetrics() *dsapi.DataStoreMetrics {
	s.mu.RLock()
	n := len(s.data)
	s.mu.RUnlock()
	return &dsapi.DataStoreMetrics{ItemCount: int64(n), LastAccess: time.Now()}
}

// Write implements dsapi.WritableStore.
func (s *e2eWritableStore) Write(source string, entry *dsapi.DataEntry) error {
	if entry == nil || entry.Key == nil || entry.Data == nil {
		return dsapi.ErrInvalidArgument
	}
	k, err := anyToString(entry.Key)
	if err != nil {
		return err
	}
	v, err := anyToString(entry.Data)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.data[k] = v
	s.sources[source] = struct{}{}
	s.mu.Unlock()
	return nil
}

// WriteBatch implements dsapi.WritableStore.
func (s *e2eWritableStore) WriteBatch(source string, entries []*dsapi.DataEntry) error {
	for _, e := range entries {
		if err := s.Write(source, e); err != nil {
			return err
		}
	}
	return nil
}

// Delete implements dsapi.WritableStore.
func (s *e2eWritableStore) Delete(source string, key *anypb.Any) error {
	if key == nil {
		return dsapi.ErrInvalidArgument
	}
	k, err := anyToString(key)
	if err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.data, k)
	s.mu.Unlock()
	return nil
}

// Clear implements dsapi.WritableStore.
func (s *e2eWritableStore) Clear(source string) error {
	s.mu.Lock()
	for k := range s.data {
		delete(s.data, k)
	}
	delete(s.sources, source)
	s.mu.Unlock()
	return nil
}

// ListSources implements dsapi.WritableStore.
func (s *e2eWritableStore) ListSources() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.sources))
	for src := range s.sources {
		out = append(out, src)
	}
	return out, nil
}

func anyToString(a *anypb.Any) (string, error) {
	if a == nil {
		return "", dsapi.ErrInvalidArgument
	}
	s, err := a.UnmarshalNew()
	if err != nil {
		return "", fmt.Errorf("unmarshal any: %w", err)
	}
	if v, ok := s.(*structpb.Value); ok && v != nil {
		return v.GetStringValue(), nil
	}
	return "", dsapi.ErrInvalidArgument
}
