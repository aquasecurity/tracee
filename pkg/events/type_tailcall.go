package events

import (
	"sync"
)

const (
	TailVfsWrite  uint32 = iota // Index of a function to be used in a bpf tailcall.
	TailVfsWritev               // Matches defined values in ebpf code for prog_array map.
	TailSendBin
	TailSendBinTP
	TailKernelWrite
	TailSchedProcessExecEventSubmit
	TailVfsRead
	TailVfsReadv
	TailExecBinprm1
	TailExecBinprm2
	TailHiddenKernelModuleProc
	TailHiddenKernelModuleKset
	TailHiddenKernelModuleModTree
	TailHiddenKernelModuleNewModOnly
	MaxTail
)

type TailCall struct {
	mapName  string
	progName string
	indexes  map[uint32]struct{}
	mutex    *sync.RWMutex
}

// NewTailCall creates a new TailCall with default values.
func NewTailCall(mapName, progName string, mapIndexes []uint32) *TailCall {
	indexes := make(map[uint32]struct{})

	for _, index := range mapIndexes {
		indexes[index] = struct{}{}
	}

	return &TailCall{
		mapName:  mapName,
		progName: progName,
		indexes:  indexes,
		mutex:    &sync.RWMutex{},
	}
}

//
// Indexes
//

// SetIndexes sets the indexes of the tailcall (thread-safe).
func (tc *TailCall) SetIndexes(idxs []uint32) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	// delete all previous indexes
	for k := range tc.indexes {
		delete(tc.indexes, k)
	}

	tc.addIndexes(idxs)
}

// GetIndexes returns a slice copy of instanced tailcall indexes (thread-safe).
func (tc *TailCall) GetIndexes() []uint32 {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()

	indexes := make([]uint32, 0, len(tc.indexes))
	for k := range tc.indexes {
		indexes = append(indexes, k)
	}

	return indexes
}

// AddIndex adds a tailcall index to the tailcall (thread-safe).
func (tc *TailCall) AddIndex(idx uint32) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	tc.indexes[idx] = struct{}{}
}

// AddIndexes adds tailcall indexes to the tailcall (thread-safe).
func (tc *TailCall) AddIndexes(idx []uint32) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	tc.addIndexes(idx)
}

// DelIndex deletes a tailcall index from the tailcall (thread-safe).
func (tc *TailCall) DelIndex(idx uint32) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	delete(tc.indexes, idx)
}

// DelIndexes deletes tailcall indexes from the tailcall (thread-safe).
func (tc *TailCall) DelIndexes(idx []uint32) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	for _, i := range idx {
		delete(tc.indexes, i)
	}
}

// GetIndexesLen returns the number of indexes in the tailcall (thread-safe).
func (tc *TailCall) GetIndexesLen() int {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()
	return len(tc.indexes)
}

// GetMapName returns the name of the tailcall map (thread-safe).
func (tc *TailCall) GetMapName() string {
	return tc.mapName
}

// GetProgName returns the name of the tailcall program (thread-safe).
func (tc *TailCall) GetProgName() string {
	return tc.progName
}

// addIndexes adds tailcall indexes to the tailcall (no locking).
func (tc *TailCall) addIndexes(idxs []uint32) {
	for _, i := range idxs {
		tc.indexes[i] = struct{}{}
	}
}
