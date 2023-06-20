package events

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// NOTE: TailCall type describes a single tail call, concurrency tests under dep_tailcalls_test.go

// TestSetIndexes tests the setting of the tail call's slice of indexes.
func TestSetIndexes(t *testing.T) {
	tc := NewTailCall("map", "prog", []uint32{1, 2, 3})

	tc.SetIndexes([]uint32{4, 5, 6})

	actualIndexes := tc.GetIndexes()
	assert.ElementsMatch(t, []uint32{4, 5, 6}, actualIndexes)
}

// TestGetIndexes tests the retrieval of the tail call's slice of indexes.
func TestGetIndexes(t *testing.T) {
	tc := NewTailCall("map", "prog", []uint32{1, 2, 3})

	actualIndexes := tc.GetIndexes()
	assert.ElementsMatch(t, []uint32{1, 2, 3}, actualIndexes)
}

// TestAddIndex tests the addition of an index to the tail call.
func TestAddIndex(t *testing.T) {
	tc := NewTailCall("map", "prog", []uint32{1, 2, 3})

	tc.AddIndex(4)

	actualIndexes := tc.GetIndexes()
	assert.ElementsMatch(t, []uint32{1, 2, 3, 4}, actualIndexes)
}

// TestAddIndexes tests the addition of multiple indexes to the tail call.
func TestAddIndexes(t *testing.T) {
	tc := NewTailCall("map", "prog", []uint32{1, 2, 3})

	tc.AddIndexes([]uint32{4, 5, 6})

	actualIndexes := tc.GetIndexes()
	assert.ElementsMatch(t, []uint32{1, 2, 3, 4, 5, 6}, actualIndexes)
}

// TestDelIndex tests the removal of an index from the tail call.
func TestDelIndex(t *testing.T) {
	tc := NewTailCall("map", "prog", []uint32{1, 2, 3, 4, 5, 6})

	tc.DelIndex(3)

	actualIndexes := tc.GetIndexes()
	assert.ElementsMatch(t, []uint32{1, 2, 4, 5, 6}, actualIndexes)
}

// TestDelIndexes tests the removal of multiple indexes from the tail call.
func TestDelIndexes(t *testing.T) {
	tc := NewTailCall("map", "prog", []uint32{1, 2, 3, 4, 5, 6})

	tc.DelIndexes([]uint32{3, 5})

	actualIndexes := tc.GetIndexes()
	assert.ElementsMatch(t, []uint32{1, 2, 4, 6}, actualIndexes)
}

// testGetMapIndexesLen tests the retrieval of the map's indexes length.
func TestGetIndexesLen(t *testing.T) {
	tc := NewTailCall("map", "prog", []uint32{1, 2, 3})

	actualLen := tc.GetIndexesLen()
	assert.Equal(t, 3, actualLen)
}

// TestGetMapName tests the retrieval of the map's name.
func TestGetMapName(t *testing.T) {
	tc := NewTailCall("map", "prog", []uint32{1, 2, 3})

	actualMapName := tc.GetMapName()
	assert.Equal(t, "map", actualMapName)
}

// TestGetProgName tests the retrieval of the program's name.
func TestGetProgName(t *testing.T) {
	tc := NewTailCall("map", "prog", []uint32{1, 2, 3})

	actualProgName := tc.GetProgName()
	assert.Equal(t, "prog", actualProgName)
}
