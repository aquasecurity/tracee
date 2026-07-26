package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/filters"
)

// newDataOnlyFilterMaps returns a filterMaps with just the data-filter outer maps
// initialized, which is all processStringFilterRule touches.
func newDataOnlyFilterMaps() *filterMaps {
	return &filterMaps{
		dataPrefixFilters: make(map[filterVersionKey]map[string][]ruleBitmap),
		dataSuffixFilters: make(map[filterVersionKey]map[string][]ruleBitmap),
		dataExactFilters:  make(map[filterVersionKey]map[string][]ruleBitmap),
	}
}

// ruleBitIsSet reports whether the given bit offset is set in the bitmap word.
func ruleBitIsSet(word uint64, offset uint) bool {
	return (word>>offset)&1 == 1
}

// Test_processStringFilterRule_exact is a regression test for an infinite loop in the
// exact-match path of processStringFilterRule. The slice-growth loop checked the length of
// the outer map (len(exactBitmaps)) instead of the per-key slice (len(eb)), so the loop body
// (which appends to the slice) never satisfied its own condition: the first exact data filter
// on an event spun forever appending ruleBitmaps, exhausting memory at policy load. It was
// observed only as an OOM kill of the integration suite on a security_file_open policy using
// exact data.pathname filters, because there was no unit coverage for this path. The prefix
// and suffix paths go through updatePrefixOrSuffixMatch and were never affected.
func Test_processStringFilterRule_exact(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		ruleID uint
	}{
		{name: "rule 0 (bitmap index 0)", ruleID: 0},
		{name: "rule 5 (bitmap index 0)", ruleID: 5},
		{name: "rule 70 (bitmap index 1, overflow)", ruleID: 70},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pm := &PolicyManager{}
			fm := newDataOnlyFilterMaps()
			vKey := filterVersionKey{Version: 1, EventID: 42}
			cfg := &stringFilterConfig{}
			eqs := filters.StringFilterEqualities{
				ExactEqual:    map[string]struct{}{"/etc/ld.so.cache": {}},
				ExactNotEqual: map[string]struct{}{"/etc/netconfig": {}},
			}

			// Run under a deadline so a reintroduced infinite loop fails the test
			// quickly and clearly instead of hanging the whole suite.
			done := make(chan struct{})
			go func() {
				defer close(done)
				pm.processStringFilterRule(fm, vKey, tc.ruleID, eqs, cfg)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("processStringFilterRule did not return: exact-match slice growth is looping on the wrong length")
			}

			idx := tc.ruleID / 64
			off := tc.ruleID % 64
			exact := fm.dataExactFilters[vKey]
			require.NotNil(t, exact)

			// equal key: equalsInRules and keyUsedInRules both set at the rule's bit.
			eqBM := exact["/etc/ld.so.cache"]
			require.Greater(t, len(eqBM), int(idx))
			assert.True(t, ruleBitIsSet(eqBM[idx].equalsInRules, off), "equal: equalsInRules bit set")
			assert.True(t, ruleBitIsSet(eqBM[idx].keyUsedInRules, off), "equal: keyUsedInRules bit set")

			// not-equal key: keyUsedInRules set, equalsInRules clear.
			neBM := exact["/etc/netconfig"]
			require.Greater(t, len(neBM), int(idx))
			assert.False(t, ruleBitIsSet(neBM[idx].equalsInRules, off), "notEqual: equalsInRules bit clear")
			assert.True(t, ruleBitIsSet(neBM[idx].keyUsedInRules, off), "notEqual: keyUsedInRules bit set")

			// config: exact enabled for the rule; matchIfKeyMissing set for the not-equal.
			require.Greater(t, len(cfg.exactEnabled), int(idx))
			assert.True(t, ruleBitIsSet(cfg.exactEnabled[idx], off), "exactEnabled bit set")
			require.Greater(t, len(cfg.exactMatchIfKeyMissing), int(idx))
			assert.True(t, ruleBitIsSet(cfg.exactMatchIfKeyMissing[idx], off), "exactMatchIfKeyMissing bit set for notEqual")
		})
	}
}

// Test_processStringFilterRule_mixed exercises exact, prefix, and suffix filters together on
// a single rule (the shape of the security_file_open policies in the integration suite that
// triggered the OOM), ensuring the combined path completes and records each match type.
func Test_processStringFilterRule_mixed(t *testing.T) {
	t.Parallel()

	pm := &PolicyManager{}
	fm := newDataOnlyFilterMaps()
	vKey := filterVersionKey{Version: 1, EventID: 42}
	cfg := &stringFilterConfig{}
	const ruleID = uint(3)

	eqs := filters.StringFilterEqualities{
		ExactEqual:     map[string]struct{}{"/etc/ld.so.cache": {}},
		ExactNotEqual:  map[string]struct{}{"/etc/netconfig": {}},
		PrefixEqual:    map[string]struct{}{"/etc/net": {}},
		PrefixNotEqual: map[string]struct{}{"/usr/lib/": {}},
		SuffixEqual:    map[string]struct{}{"libc.so.6": {}},
		SuffixNotEqual: map[string]struct{}{"libtinfo.so.6.3": {}},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		pm.processStringFilterRule(fm, vKey, ruleID, eqs, cfg)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("processStringFilterRule did not return on mixed exact/prefix/suffix filters")
	}

	off := ruleID % 64
	require.NotEmpty(t, fm.dataExactFilters[vKey])
	require.NotEmpty(t, fm.dataPrefixFilters[vKey])
	require.NotEmpty(t, fm.dataSuffixFilters[vKey])

	require.NotEmpty(t, cfg.exactEnabled)
	require.NotEmpty(t, cfg.prefixEnabled)
	require.NotEmpty(t, cfg.suffixEnabled)
	assert.True(t, ruleBitIsSet(cfg.exactEnabled[0], off), "exact enabled")
	assert.True(t, ruleBitIsSet(cfg.prefixEnabled[0], off), "prefix enabled")
	assert.True(t, ruleBitIsSet(cfg.suffixEnabled[0], off), "suffix enabled")
}
