package events

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// NOTE: TailCall type describes a single tail call, concurrency tests under dep_tailcalls_test.go

// TestTailCallSetIndexes tests the setting of the tail call's slice of indexes.
func TestTailCallSetIndexes(t *testing.T) {
	tc := NewTailCall("map", "prog", []uint32{1, 2, 3})

	tc.SetIndexes([]uint32{4, 5, 6})

	actualIndexes := tc.GetIndexes()
	require.ElementsMatch(t, []uint32{4, 5, 6}, actualIndexes)
}

// TestTailCallGetIndexes tests the retrieval of the tail call's slice of indexes.
func TestTailCallGetIndexes(t *testing.T) {
	tc := NewTailCall("map", "prog", []uint32{1, 2, 3})

	actualIndexes := tc.GetIndexes()
	require.ElementsMatch(t, []uint32{1, 2, 3}, actualIndexes)
}

// TestTailCallAddIndex tests the addition of an index to the tail call.
func TestTailCallAddIndex(t *testing.T) {
	tc := NewTailCall("map", "prog", []uint32{1, 2, 3})

	tc.AddIndex(4)

	actualIndexes := tc.GetIndexes()
	require.ElementsMatch(t, []uint32{1, 2, 3, 4}, actualIndexes)
}

// TestTailCallAddIndexes tests the addition of multiple indexes to the tail call.
func TestTailCallAddIndexes(t *testing.T) {
	tc := NewTailCall("map", "prog", []uint32{1, 2, 3})

	tc.AddIndexes([]uint32{4, 5, 6})

	actualIndexes := tc.GetIndexes()
	require.ElementsMatch(t, []uint32{1, 2, 3, 4, 5, 6}, actualIndexes)
}

// TestTailCallDelIndex tests the removal of an index from the tail call.
func TestTailCallDelIndex(t *testing.T) {
	tc := NewTailCall("map", "prog", []uint32{1, 2, 3, 4, 5, 6})

	tc.DelIndex(3)

	actualIndexes := tc.GetIndexes()
	require.ElementsMatch(t, []uint32{1, 2, 4, 5, 6}, actualIndexes)
}

// TestTailCallDelIndexes tests the removal of multiple indexes from the tail call.
func TestTailCallDelIndexes(t *testing.T) {
	tc := NewTailCall("map", "prog", []uint32{1, 2, 3, 4, 5, 6})

	tc.DelIndexes([]uint32{3, 5})

	actualIndexes := tc.GetIndexes()
	require.ElementsMatch(t, []uint32{1, 2, 4, 6}, actualIndexes)
}

// testGetMapIndexesLen tests the retrieval of the map's indexes length.
func TestTailCallGetIndexesLen(t *testing.T) {
	tc := NewTailCall("map", "prog", []uint32{1, 2, 3})

	actualLen := tc.GetIndexesLen()
	require.Equal(t, 3, actualLen)
}

// TestTailCallGetMapName tests the retrieval of the map's name.
func TestTailCallGetMapName(t *testing.T) {
	tc := NewTailCall("map", "prog", []uint32{1, 2, 3})

	actualMapName := tc.GetMapName()
	require.Equal(t, "map", actualMapName)
}

// TestTailCallGetProgName tests the retrieval of the program's name.
func TestTailCallGetProgName(t *testing.T) {
	tc := NewTailCall("map", "prog", []uint32{1, 2, 3})

	actualProgName := tc.GetProgName()
	require.Equal(t, "prog", actualProgName)
}
