package detect

import (
	"sync"

	"github.com/aquasecurity/tracee/types/protocol"
)

// Finding is the main output of a signature. It represents a match result for the signature business logic
type Finding struct {
	dataLock sync.RWMutex
	// Data contains useful information about the context of the finding
	// added by signature authors.
	//
	// Deprecated: direct access to the Data field is allowed for historic reasons, but is unsafe.
	// The following methods should be used instead: AddDataEntry, AddDataEntries and GetData.
	Data        map[string]interface{}
	Event       protocol.Event // Event is the causal event of the Finding
	SigMetadata SignatureMetadata
}

func (f *Finding) AddDataEntry(key string, data interface{}) {
	f.dataLock.Lock()
	defer f.dataLock.Unlock()

	if f.Data == nil {
		f.Data = make(map[string]interface{}, 1)
	}

	f.Data[key] = data
}

func (f *Finding) AddDataEntries(dataBatch map[string]interface{}) {
	f.dataLock.Lock()
	defer f.dataLock.Unlock()

	if f.Data == nil {
		f.Data = make(map[string]interface{}, len(dataBatch))
	}

	copyMap(f.Data, dataBatch)
}

func (f *Finding) GetData() map[string]interface{} {
	f.dataLock.RLock()
	defer f.dataLock.RUnlock()

	if f.Data == nil {
		return map[string]interface{}{}
	}

	res := make(map[string]interface{}, len(f.Data))
	copyMap(res, f.Data)
	return res
}

// copyMap is a copy of the Copy function from "golang.org/x/exp/maps", as it is an experimental repo.
// copyMap copies all key/value pairs in src adding them to dst.
// When a key in src is already present in dst,
// the value in dst will be overwritten by the value associated
// with the key in src.
func copyMap[M1 ~map[K]V, M2 ~map[K]V, K comparable, V any](dst M1, src M2) {
	for k, v := range src {
		dst[k] = v
	}
}

// findingDataStruct is the interface that types returned by signatures Data should implement to be
// serialized to protobuf when using GRPC
type FindingDataStruct interface {
	// ToMap converts the data to a map[string]interface{} for serialization
	ToMap() map[string]interface{}
}
