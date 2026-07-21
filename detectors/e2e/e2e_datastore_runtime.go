//go:build e2e

package e2e

import (
	"google.golang.org/protobuf/types/known/anypb"

	dsapi "github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// e2eRuntime is a minimal datastores.Runtime that wraps a single e2e writable
// store. It lets the single production DataStoreService serve the e2e store
// without registering a separate e2e-specific gRPC service.
type e2eRuntime struct {
	name  string
	store dsapi.WritableStore
}

// NewE2eRuntime returns a datastores.Runtime that owns exactly one writable
// store, identified by name.
func NewE2eRuntime(name string, store dsapi.WritableStore) dsapi.Runtime {
	return &e2eRuntime{name: name, store: store}
}

// guard returns ErrRuntimeStoreNotFound when storeName is not the store owned
// by this runtime.
func (r *e2eRuntime) guard(storeName string) error {
	if storeName != r.name {
		return dsapi.ErrRuntimeStoreNotFound
	}
	return nil
}

// Stores returns the names of the writable stores this runtime owns.
func (r *e2eRuntime) Stores() []string {
	return []string{r.name}
}

// WriteData writes a single entry from a source to the named store.
func (r *e2eRuntime) WriteData(storeName, source string, entry *dsapi.DataEntry) error {
	if err := r.guard(storeName); err != nil {
		return err
	}
	return r.store.Write(source, entry)
}

// WriteBatchData writes multiple entries from a source to the named store.
func (r *e2eRuntime) WriteBatchData(storeName, source string, entries []*dsapi.DataEntry) error {
	if err := r.guard(storeName); err != nil {
		return err
	}
	return r.store.WriteBatch(source, entries)
}

// DeleteData removes a specific key from a source in the named store.
func (r *e2eRuntime) DeleteData(storeName, source string, key *anypb.Any) error {
	if err := r.guard(storeName); err != nil {
		return err
	}
	return r.store.Delete(source, key)
}

// ClearSource removes all data from a specific source in the named store.
func (r *e2eRuntime) ClearSource(storeName, source string) error {
	if err := r.guard(storeName); err != nil {
		return err
	}
	return r.store.Clear(source)
}

// ListSources returns all source identifiers that have data in the named store.
func (r *e2eRuntime) ListSources(storeName string) ([]string, error) {
	if err := r.guard(storeName); err != nil {
		return nil, err
	}
	return r.store.ListSources()
}
