package bufferdecoder

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

// Note: because of memory alignment, unsafe.Sizeof doesn't return the sum of byte size of each fields.
// Thus, in order to the test to be appropriate (and fail if any change to the struct is done without updating GetSizeBytes), we need
// to find a function that relates GetSizeBytes and the actual size of the struct calculated with unsafe.Sizeof.

// If the test is failing then this means you added/moved the fields inside in the type of variable v.
// If so, then this means you need to update the decoder functions and GetSizeBytes functions.

func TestContextSize(t *testing.T) {
	var v Context
	size := int(unsafe.Sizeof(v))
	assert.Equal(t, size, int(v.GetSizeBytes()))
}
func TestChunkMetaSize(t *testing.T) {
	var v ChunkMeta
	size := int(unsafe.Sizeof(v))
	assert.Equal(t, size-7, int(v.GetSizeBytes()))
}

func TestVfsWriteMetaSize(t *testing.T) {
	var v VfsWriteMeta
	size := int(unsafe.Sizeof(v))
	assert.Equal(t, size-4, int(v.GetSizeBytes()))
}

func TestKernelModuleMetaSize(t *testing.T) {
	var v KernelModuleMeta
	size := int(unsafe.Sizeof(v))
	assert.Equal(t, size-4, int(v.GetSizeBytes()))
}

func TestBpfObjectMetaSize(t *testing.T) {
	var v BpfObjectMeta
	size := int(unsafe.Sizeof(v))
	assert.Equal(t, size, int(v.GetSizeBytes()))
}

func TestMprotectWriteMetaSize(t *testing.T) {
	var v MprotectWriteMeta
	size := int(unsafe.Sizeof(v))
	assert.Equal(t, size-4, int(v.GetSizeBytes()))
}
