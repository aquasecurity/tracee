package grpc

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

const (
	fakeStoreAlpha = "fake_store_alpha"
	fakeStoreBeta  = "fake_store_beta"
)

// fakeStore is a minimal WritableStore for exercising the gRPC dispatch layer.
type fakeStore struct {
	name    string
	opErr   error // returned by mutating ops
	writes  int
	batches int
	deletes int
	clears  int
	sources []string
	srcErr  error
}

func (f *fakeStore) Name() string { return f.name }
func (f *fakeStore) GetHealth() *datastores.HealthInfo {
	return &datastores.HealthInfo{Status: datastores.HealthHealthy}
}
func (f *fakeStore) GetMetrics() *datastores.DataStoreMetrics { return &datastores.DataStoreMetrics{} }

func (f *fakeStore) Write(string, *datastores.DataEntry) error {
	if f.opErr != nil {
		return f.opErr
	}
	f.writes++
	return nil
}

func (f *fakeStore) WriteBatch(_ string, _ []*datastores.DataEntry) error {
	if f.opErr != nil {
		return f.opErr
	}
	f.batches++
	return nil
}

func (f *fakeStore) Delete(string, *anypb.Any) error {
	if f.opErr != nil {
		return f.opErr
	}
	f.deletes++
	return nil
}

func (f *fakeStore) Clear(string) error {
	if f.opErr != nil {
		return f.opErr
	}
	f.clears++
	return nil
}

func (f *fakeStore) ListSources() ([]string, error) {
	if f.srcErr != nil {
		return nil, f.srcErr
	}
	return f.sources, nil
}

type fakeRuntime struct {
	stores    map[string]datastores.WritableStore
	supported bool
}

func newFakeRuntime(stores map[string]datastores.WritableStore, supported bool) *fakeRuntime {
	return &fakeRuntime{stores: stores, supported: supported}
}

func (r *fakeRuntime) getStore(name string) (datastores.WritableStore, error) {
	store, ok := r.stores[name]
	if !ok {
		return nil, datastores.ErrRuntimeStoreNotFound
	}
	return store, nil
}

func (r *fakeRuntime) Stores() []string {
	names := make([]string, 0, len(r.stores))
	for name := range r.stores {
		names = append(names, name)
	}
	return names
}

func (r *fakeRuntime) WriteData(storeName, source string, entry *datastores.DataEntry) error {
	if !r.supported {
		return fmt.Errorf("runtime unavailable: %w", datastores.ErrRuntimeUnsupported)
	}
	store, err := r.getStore(storeName)
	if err != nil {
		return err
	}
	return store.Write(source, entry)
}

func (r *fakeRuntime) WriteBatchData(storeName, source string, entries []*datastores.DataEntry) error {
	if !r.supported {
		return fmt.Errorf("runtime unavailable: %w", datastores.ErrRuntimeUnsupported)
	}
	store, err := r.getStore(storeName)
	if err != nil {
		return err
	}
	return store.WriteBatch(source, entries)
}

func (r *fakeRuntime) DeleteData(storeName, source string, key *anypb.Any) error {
	if !r.supported {
		return fmt.Errorf("runtime unavailable: %w", datastores.ErrRuntimeUnsupported)
	}
	store, err := r.getStore(storeName)
	if err != nil {
		return err
	}
	return store.Delete(source, key)
}

func (r *fakeRuntime) ClearSource(storeName, source string) error {
	if !r.supported {
		return fmt.Errorf("runtime unavailable: %w", datastores.ErrRuntimeUnsupported)
	}
	store, err := r.getStore(storeName)
	if err != nil {
		return err
	}
	return store.Clear(source)
}

func (r *fakeRuntime) ListSources(storeName string) ([]string, error) {
	store, err := r.getStore(storeName)
	if err != nil {
		return nil, err
	}
	return store.ListSources()
}

func wantCode(t *testing.T, err error, code codes.Code) {
	t.Helper()
	if status.Code(err) != code {
		t.Fatalf("expected gRPC code %v, got %v (err=%v)", code, status.Code(err), err)
	}
}

func TestDataStoreService_UnknownStore(t *testing.T) {
	svc := NewDataStoreService()

	_, err := svc.WriteData(context.Background(), &datastores.WriteDataRequest{StoreName: "missing"})
	wantCode(t, err, codes.NotFound)
}

func TestDataStoreService_RuntimeWrite(t *testing.T) {
	fs := &fakeStore{name: fakeStoreAlpha}
	svc := NewDataStoreService(newFakeRuntime(map[string]datastores.WritableStore{fs.name: fs}, true))

	_, err := svc.WriteData(context.Background(), &datastores.WriteDataRequest{
		StoreName: fakeStoreAlpha,
		Source:    "feed",
		Entry:     &datastores.DataEntry{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fs.writes != 1 {
		t.Fatalf("expected 1 write, got %d", fs.writes)
	}
}

func TestDataStoreService_InvalidArgumentMapsToInvalidArgument(t *testing.T) {
	fs := &fakeStore{name: fakeStoreAlpha, opErr: fmt.Errorf("bad key: %w", datastores.ErrInvalidArgument)}
	svc := NewDataStoreService(newFakeRuntime(map[string]datastores.WritableStore{fs.name: fs}, true))

	_, err := svc.WriteData(context.Background(), &datastores.WriteDataRequest{
		StoreName: fakeStoreAlpha,
		Entry:     &datastores.DataEntry{},
	})
	wantCode(t, err, codes.InvalidArgument)
}

func TestDataStoreService_NotImplementedMapsToUnimplemented(t *testing.T) {
	fs := &fakeStore{name: fakeStoreAlpha, opErr: fmt.Errorf("nope: %w", datastores.ErrNotImplemented)}
	svc := NewDataStoreService(newFakeRuntime(map[string]datastores.WritableStore{fs.name: fs}, true))

	_, err := svc.DeleteData(context.Background(), &datastores.DeleteDataRequest{StoreName: fakeStoreAlpha})
	wantCode(t, err, codes.Unimplemented)
}

func TestDataStoreService_GenericErrorMapsToInternal(t *testing.T) {
	fs := &fakeStore{name: fakeStoreAlpha, opErr: errors.New("disk on fire")}
	svc := NewDataStoreService(newFakeRuntime(map[string]datastores.WritableStore{fs.name: fs}, true))

	_, err := svc.ClearSource(context.Background(), &datastores.ClearSourceRequest{StoreName: fakeStoreAlpha})
	wantCode(t, err, codes.Internal)
}

func TestDataStoreService_WriteBatchCountsEntries(t *testing.T) {
	fs := &fakeStore{name: fakeStoreAlpha}
	svc := NewDataStoreService(newFakeRuntime(map[string]datastores.WritableStore{fs.name: fs}, true))

	resp, err := svc.WriteBatchData(context.Background(), &datastores.WriteBatchDataRequest{
		StoreName: fakeStoreAlpha,
		Entries:   []*datastores.DataEntry{{}, {}, {}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.WrittenCount != 3 {
		t.Fatalf("expected written_count 3, got %d", resp.WrittenCount)
	}
}

func TestDataStoreService_ListSources(t *testing.T) {
	fs := &fakeStore{name: fakeStoreAlpha, sources: []string{"feed_a", "feed_b"}}
	svc := NewDataStoreService(newFakeRuntime(map[string]datastores.WritableStore{fs.name: fs}, true))

	resp, err := svc.ListSources(context.Background(), &datastores.ListSourcesRequest{StoreName: fakeStoreAlpha})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Sources) != 2 {
		t.Fatalf("expected 2 sources, got %v", resp.Sources)
	}
}

func TestDataStoreService_MultipleRuntimes(t *testing.T) {
	alphaStore := &fakeStore{name: fakeStoreAlpha}
	betaStore := &fakeStore{name: fakeStoreBeta}

	svc := NewDataStoreService(
		newFakeRuntime(map[string]datastores.WritableStore{alphaStore.name: alphaStore}, true),
		newFakeRuntime(map[string]datastores.WritableStore{betaStore.name: betaStore}, true),
	)

	_, err := svc.WriteData(context.Background(), &datastores.WriteDataRequest{
		StoreName: fakeStoreBeta,
		Source:    "feed",
		Entry:     &datastores.DataEntry{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if betaStore.writes != 1 {
		t.Fatalf("expected beta store write, got %d", betaStore.writes)
	}
	if alphaStore.writes != 0 {
		t.Fatalf("expected alpha store untouched, got %d", alphaStore.writes)
	}
}

func TestDataStoreService_MultipleRuntimes_RoutesAlpha(t *testing.T) {
	alphaStore := &fakeStore{name: fakeStoreAlpha}
	betaStore := &fakeStore{name: fakeStoreBeta}

	svc := NewDataStoreService(
		newFakeRuntime(map[string]datastores.WritableStore{alphaStore.name: alphaStore}, true),
		newFakeRuntime(map[string]datastores.WritableStore{betaStore.name: betaStore}, true),
	)

	_, err := svc.WriteData(context.Background(), &datastores.WriteDataRequest{
		StoreName: fakeStoreAlpha,
		Source:    "feed",
		Entry:     &datastores.DataEntry{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alphaStore.writes != 1 {
		t.Fatalf("expected alpha store write, got %d", alphaStore.writes)
	}
	if betaStore.writes != 0 {
		t.Fatalf("expected beta store untouched, got %d", betaStore.writes)
	}
}

func TestDataStoreService_MultipleRuntimes_ListSourcesPerStore(t *testing.T) {
	alphaStore := &fakeStore{name: fakeStoreAlpha, sources: []string{"alpha_feed"}}
	betaStore := &fakeStore{name: fakeStoreBeta, sources: []string{"beta_feed_a", "beta_feed_b"}}

	svc := NewDataStoreService(
		newFakeRuntime(map[string]datastores.WritableStore{alphaStore.name: alphaStore}, true),
		newFakeRuntime(map[string]datastores.WritableStore{betaStore.name: betaStore}, true),
	)

	alphaResp, err := svc.ListSources(context.Background(), &datastores.ListSourcesRequest{StoreName: fakeStoreAlpha})
	if err != nil {
		t.Fatalf("unexpected alpha list error: %v", err)
	}
	if len(alphaResp.Sources) != 1 || alphaResp.Sources[0] != "alpha_feed" {
		t.Fatalf("unexpected alpha sources: %v", alphaResp.Sources)
	}

	betaResp, err := svc.ListSources(context.Background(), &datastores.ListSourcesRequest{StoreName: fakeStoreBeta})
	if err != nil {
		t.Fatalf("unexpected beta list error: %v", err)
	}
	if len(betaResp.Sources) != 2 {
		t.Fatalf("expected 2 beta sources, got %v", betaResp.Sources)
	}
}

func TestDataStoreService_UnsupportedRuntime(t *testing.T) {
	fs := &fakeStore{name: fakeStoreAlpha}
	svc := NewDataStoreService(newFakeRuntime(map[string]datastores.WritableStore{fs.name: fs}, false))

	_, err := svc.WriteData(context.Background(), &datastores.WriteDataRequest{StoreName: fakeStoreAlpha})
	wantCode(t, err, codes.Unimplemented)
}

// TestDataStoreService_DuplicateStoreAcrossRuntimes verifies that when two
// runtimes claim the same store name (a misconfiguration), the first
// registration wins and the write is routed to it.
func TestDataStoreService_DuplicateStoreAcrossRuntimes(t *testing.T) {
	first := &fakeStore{name: fakeStoreAlpha}
	second := &fakeStore{name: fakeStoreAlpha}
	svc := NewDataStoreService(
		newFakeRuntime(map[string]datastores.WritableStore{first.name: first}, true),
		newFakeRuntime(map[string]datastores.WritableStore{second.name: second}, true),
	)

	_, err := svc.WriteData(context.Background(), &datastores.WriteDataRequest{
		StoreName: fakeStoreAlpha,
		Entry:     &datastores.DataEntry{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if first.writes != 1 {
		t.Fatalf("expected first-registered store to win, got %d writes", first.writes)
	}
	if second.writes != 0 {
		t.Fatalf("expected second store untouched, got %d writes", second.writes)
	}
}

// TestDataStoreService_StoreUnhealthyMapsToUnavailable documents that a store
// op returning ErrStoreUnhealthy surfaces as the retryable Unavailable code
// rather than Internal.
func TestDataStoreService_StoreUnhealthyMapsToUnavailable(t *testing.T) {
	fs := &fakeStore{name: fakeStoreAlpha, opErr: fmt.Errorf("backend down: %w", datastores.ErrStoreUnhealthy)}
	svc := NewDataStoreService(newFakeRuntime(map[string]datastores.WritableStore{fs.name: fs}, true))

	_, err := svc.WriteData(context.Background(), &datastores.WriteDataRequest{
		StoreName: fakeStoreAlpha,
		Entry:     &datastores.DataEntry{},
	})
	wantCode(t, err, codes.Unavailable)
}

// TestDataStoreService_WriteIndependentOfListSources verifies that routing no
// longer depends on ListSources: a write succeeds even when the store's
// ListSources would fail, because dispatch uses the store-name index built at
// construction rather than probing each runtime on the hot path.
func TestDataStoreService_WriteIndependentOfListSources(t *testing.T) {
	fs := &fakeStore{name: fakeStoreAlpha, srcErr: errors.New("list backend unreachable")}
	svc := NewDataStoreService(newFakeRuntime(map[string]datastores.WritableStore{fs.name: fs}, true))

	_, err := svc.WriteData(context.Background(), &datastores.WriteDataRequest{
		StoreName: fakeStoreAlpha,
		Entry:     &datastores.DataEntry{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fs.writes != 1 {
		t.Fatalf("expected 1 write despite failing ListSources, got %d", fs.writes)
	}
}
