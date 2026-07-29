package policy

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

// Test_GoCLayoutContract guards the byte layout of the Go structs that are written verbatim into
// BPF maps (via unsafe.Pointer) and therefore MUST stay byte-compatible with their C counterparts.
// A size/offset drift here (an added or reordered field) would otherwise become a silent runtime
// mismatch, exactly the class of bug behind the filter_version_key padding regression.
func Test_GoCLayoutContract(t *testing.T) {
	t.Parallel()

	// C filter_version_key_t { u16 version; u32 event_id; } -> 8 bytes with 2 bytes of implicit
	// padding after version; event_id lands at offset 4. The Go struct's explicit Pad field keeps
	// the inserted key's padding bytes zeroed so kernel HASH_OF_MAPS lookups match.
	require.Equal(t, uintptr(8), unsafe.Sizeof(filterVersionKey{}), "filterVersionKey size")
	require.Equal(t, uintptr(0), unsafe.Offsetof(filterVersionKey{}.Version), "Version offset")
	require.Equal(t, uintptr(4), unsafe.Offsetof(filterVersionKey{}.EventID), "EventID offset")

	// C event_config_t: the value type of events_config_map (bpftool reports value 288B).
	require.Equal(t, uintptr(288), unsafe.Sizeof(eventConfig{}), "eventConfig size")
	require.Equal(t, uintptr(0), unsafe.Offsetof(eventConfig{}.rulesVersion), "rulesVersion offset")
	require.Equal(t, uintptr(2), unsafe.Offsetof(eventConfig{}.hasOverflow), "hasOverflow offset")
	require.Equal(t, uintptr(8), unsafe.Offsetof(eventConfig{}.submitForRules), "submitForRules offset")
	require.Equal(t, uintptr(16), unsafe.Offsetof(eventConfig{}.fieldTypes), "fieldTypes offset")
	require.Equal(t, uintptr(24), unsafe.Offsetof(eventConfig{}.scopeFilters), "scopeFilters offset")
	require.Equal(t, uintptr(240), unsafe.Offsetof(eventConfig{}.dataFilter), "dataFilter offset")

	// C scope_filters_config_t: 27 x u64. The size can never catch a field-order swap (any
	// permutation keeps 216 bytes while completely scrambling the kernel's per-dimension
	// semantics), so every field's offset is pinned in C declaration order.
	var sfc scopeFiltersConfig
	require.Equal(t, uintptr(216), unsafe.Sizeof(sfc), "scopeFiltersConfig size")
	for i, off := range []uintptr{
		unsafe.Offsetof(sfc.UIDFilterEnabled),
		unsafe.Offsetof(sfc.PIDFilterEnabled),
		unsafe.Offsetof(sfc.MntNsFilterEnabled),
		unsafe.Offsetof(sfc.PidNsFilterEnabled),
		unsafe.Offsetof(sfc.UtsNsFilterEnabled),
		unsafe.Offsetof(sfc.CommFilterEnabled),
		unsafe.Offsetof(sfc.CgroupIdFilterEnabled),
		unsafe.Offsetof(sfc.ContFilterEnabled),
		unsafe.Offsetof(sfc.NewContFilterEnabled),
		unsafe.Offsetof(sfc.ContStartedFilterEnabled),
		unsafe.Offsetof(sfc.NewPidFilterEnabled),
		unsafe.Offsetof(sfc.ProcTreeFilterEnabled),
		unsafe.Offsetof(sfc.BinPathFilterEnabled),
		unsafe.Offsetof(sfc.FollowFilterEnabled),
		unsafe.Offsetof(sfc.UIDFilterMatchIfKeyMissing),
		unsafe.Offsetof(sfc.PIDFilterMatchIfKeyMissing),
		unsafe.Offsetof(sfc.MntNsFilterMatchIfKeyMissing),
		unsafe.Offsetof(sfc.PidNsFilterMatchIfKeyMissing),
		unsafe.Offsetof(sfc.UtsNsFilterMatchIfKeyMissing),
		unsafe.Offsetof(sfc.CommFilterMatchIfKeyMissing),
		unsafe.Offsetof(sfc.CgroupIdFilterMatchIfKeyMissing),
		unsafe.Offsetof(sfc.ContFilterMatchIfKeyMissing),
		unsafe.Offsetof(sfc.NewContFilterMatchIfKeyMissing),
		unsafe.Offsetof(sfc.ContStartedFilterMatchIfKeyMissing),
		unsafe.Offsetof(sfc.NewPidFilterMatchIfKeyMissing),
		unsafe.Offsetof(sfc.ProcTreeFilterMatchIfKeyMissing),
		unsafe.Offsetof(sfc.BinPathFilterMatchIfKeyMissing),
	} {
		require.Equal(t, uintptr(i*8), off, "scopeFiltersConfig field %d offset (order must match scope_filters_config_t)", i)
	}

	// C string_filter_config_t (inside data_filter_config_t): 6 x u64.
	var dfc dataFilterConfigBPF
	require.Equal(t, uintptr(48), unsafe.Sizeof(dfc), "dataFilterConfigBPF size")
	require.Equal(t, uintptr(0), unsafe.Offsetof(dfc.string.prefixEnabled), "prefixEnabled offset")
	require.Equal(t, uintptr(8), unsafe.Offsetof(dfc.string.suffixEnabled), "suffixEnabled offset")
	require.Equal(t, uintptr(16), unsafe.Offsetof(dfc.string.exactEnabled), "exactEnabled offset")
	require.Equal(t, uintptr(24), unsafe.Offsetof(dfc.string.prefixMatchIfKeyMissing), "prefixMatchIfKeyMissing offset")
	require.Equal(t, uintptr(32), unsafe.Offsetof(dfc.string.suffixMatchIfKeyMissing), "suffixMatchIfKeyMissing offset")
	require.Equal(t, uintptr(40), unsafe.Offsetof(dfc.string.exactMatchIfKeyMissing), "exactMatchIfKeyMissing offset")

	// C tree_group_rules_t / tree_rule_table_t / event_tree_config_t: the C side has
	// _Static_asserts (types.h); these are the Go-side mirrors so an edit on either side
	// breaks a build/test instead of the runtime layout.
	require.Equal(t, uintptr(16), unsafe.Sizeof(treeGroupRules{}), "treeGroupRules size")
	require.Equal(t, uintptr(0), unsafe.Offsetof(treeGroupRules{}.Group), "Group offset")
	require.Equal(t, uintptr(8), unsafe.Offsetof(treeGroupRules{}.Rules), "Rules offset")
	require.Equal(t, uintptr(136), unsafe.Sizeof(treeRuleTable{}), "treeRuleTable size")
	require.Equal(t, uintptr(0), unsafe.Offsetof(treeRuleTable{}.NumGroups), "NumGroups offset")
	require.Equal(t, uintptr(8), unsafe.Offsetof(treeRuleTable{}.Groups), "Groups offset")
	require.Equal(t, uintptr(272), unsafe.Sizeof(eventTreeConfig{}), "eventTreeConfig size")
	require.Equal(t, uintptr(136), unsafe.Offsetof(eventTreeConfig{}.followTable), "followTable offset")

	// C eq_t {u64 equals_in_rules; u64 key_used_in_rules} and the hand-rolled
	// binary.LittleEndian writes that assume equals at 0 and key_used at 8.
	require.Equal(t, uintptr(16), unsafe.Sizeof(ruleBitmap{}), "ruleBitmap size (eq_t)")
	require.Equal(t, uintptr(0), unsafe.Offsetof(ruleBitmap{}.equalsInRules), "equalsInRules offset")
	require.Equal(t, uintptr(8), unsafe.Offsetof(ruleBitmap{}.keyUsedInRules), "keyUsedInRules offset")

	// C proc_info_t prefix mirrored by Go procInfo: new_proc at 0, follow_in_scopes at 8,
	// binary {mnt_id, path[4096?]} - the Go mirror stops at binary_no_mnt; the kernel value is
	// LARGER (trailing file_info_t interpreter), which populateProcInfoMap accounts for by
	// working on full-value buffers. The follow sweep also depends on follow_in_scopes at 8.
	require.Equal(t, uintptr(0), unsafe.Offsetof(procInfo{}.newProc), "newProc offset")
	require.Equal(t, uintptr(8), unsafe.Offsetof(procInfo{}.followPolicies), "followPolicies offset")
	require.Equal(t, uintptr(16), unsafe.Offsetof(procInfo{}.mntNS), "mntNS offset")
	require.Equal(t, uintptr(20), unsafe.Offsetof(procInfo{}.binaryBytes), "binaryBytes offset")
}
