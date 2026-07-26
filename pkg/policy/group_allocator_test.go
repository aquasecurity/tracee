package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Test_GroupAllocator_StableAcrossRemoval guards the correctness requirement behind stable
// tree/follow group indices: a policy's group bit persists in KERNEL per-process state, so a
// surviving policy must never shift onto a removed policy's bit, and a retired bit must not be
// handed out again until it has been swept from the kernel maps.
func Test_GroupAllocator_StableAcrossRemoval(t *testing.T) {
	t.Parallel()

	a := newGroupAllocator(64)

	gA, err := a.getOrAssign("aaa")
	require.NoError(t, err)
	gB, err := a.getOrAssign("bbb")
	require.NoError(t, err)
	require.NotEqual(t, gA, gB)

	// Removing the FIRST-sorted policy must not shift the survivor (the positional-assignment
	// bug this allocator replaces).
	a.reconcile(map[string]bool{"bbb": true})
	gB2, err := a.getOrAssign("bbb")
	require.NoError(t, err)
	require.Equal(t, gB, gB2, "survivor's group index must be stable across another policy's removal")

	// The retired index is quarantined: a NEW policy must not inherit it before the kernel
	// sweep (stale per-process membership bits would attach the wrong subtree to it)...
	gC, err := a.getOrAssign("ccc")
	require.NoError(t, err)
	require.NotEqual(t, gA, gC, "retired index must not be reused before the kernel sweep")
	require.Equal(t, uint64(1)<<gA, a.pendingMask(), "retired index must be pending sweep")

	// ...and, with the two-generation quarantine (sweep-vs-fork mitigation), it stays quarantined
	// through the FIRST sweepDone (moved to the second-pass set) and is re-swept...
	a.sweepDone()
	require.Equal(t, uint64(1)<<gA, a.pendingMask(), "index must get a second sweep pass")
	gC2, err := a.getOrAssign("ccc2")
	require.NoError(t, err)
	require.NotEqual(t, gA, gC2, "index must not be reused after only one sweep")

	// ...becoming reusable only after the SECOND sweepDone.
	a.sweepDone()
	require.Zero(t, a.pendingMask())
	gD, err := a.getOrAssign("ddd")
	require.NoError(t, err)
	require.Equal(t, gA, gD, "twice-swept index is the smallest free one and may be reused")
}

// Test_GroupAllocator_LimitCountsPending: quarantined (unswept) indices still occupy capacity,
// so exhaustion errors instead of silently reusing an unswept bit.
func Test_GroupAllocator_LimitCountsPending(t *testing.T) {
	t.Parallel()

	a := newGroupAllocator(2)
	_, err := a.getOrAssign("aaa")
	require.NoError(t, err)
	_, err = a.getOrAssign("bbb")
	require.NoError(t, err)

	a.reconcile(map[string]bool{"bbb": true}) // retire "aaa" -> pending, capacity still consumed

	_, err = a.getOrAssign("ccc")
	require.Error(t, err, "a pending (unswept) index must not satisfy a new allocation")

	a.sweepDone() // first pass: still quarantined (second-generation)
	_, err = a.getOrAssign("ccc")
	require.Error(t, err, "an index swept only once must still not satisfy a new allocation")

	a.sweepDone() // second pass: released
	_, err = a.getOrAssign("ccc")
	require.NoError(t, err, "after the second sweep the freed index is allocatable")
}
