package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/policy"
)

func TestValidRulesMask(t *testing.T) {
	t.Parallel()

	cases := []struct {
		rulesCount uint
		word       int
		want       uint64
	}{
		{rulesCount: 70, word: 0, want: ^uint64(0)},             // word 0 fully valid
		{rulesCount: 70, word: 1, want: (uint64(1) << 6) - 1},   // rules 64..69 -> 6 low bits
		{rulesCount: 64, word: 1, want: 0},                      // no rules in word 1
		{rulesCount: 65, word: 1, want: 1},                      // only rule 64
		{rulesCount: 128, word: 1, want: ^uint64(0)},            // word 1 fully valid
		{rulesCount: 100, word: 1, want: (uint64(1) << 36) - 1}, // rules 64..99 -> 36 low bits
		{rulesCount: 100, word: 2, want: 0},                     // beyond the rules
	}

	for _, c := range cases {
		got := validRulesMask(c.rulesCount, c.word)
		assert.Equalf(t, c.want, got, "validRulesMask(%d, %d)", c.rulesCount, c.word)
	}
}

// TestApplyOverflowScopeFilter exercises the per-overflow-word equality formula
// res &= (equals | (match_if_key_missing & ~key_used)) | ~filter_enabled, mirroring eBPF.
// All cases use a single overflow rule = rule 64 (bit 0 of word 1).
func TestApplyOverflowScopeFilter(t *testing.T) {
	t.Parallel()

	const rule64 = uint64(0b1) // bit 0 of word 1
	enabled := []uint64{0, rule64}
	defaultNoMatch := []uint64{0, 0}    // e.g. comm= (match only on exact key)
	defaultMatch := []uint64{0, rule64} // e.g. comm!= (match unless excluded key)

	// match(equals, keyUsed) builds the per-word looked-up bitmaps for the key.
	match := func(equals, keyUsed uint64) []policy.RuleBitmap {
		return []policy.RuleBitmap{{}, {EqualsInRules: equals, KeyUsedInRules: keyUsed}}
	}

	cases := []struct {
		name     string
		bitmaps  []policy.RuleBitmap
		enabled  []uint64
		missing  []uint64
		wantRule bool // should rule 64 survive in word 1?
	}{
		// equal filter (comm=X): rule survives iff the key matched (equals set)
		{"equal: key matches", match(rule64, rule64), enabled, defaultNoMatch, true},
		{"equal: key absent", nil, enabled, defaultNoMatch, false},
		// not-equal filter (comm!=X): rule survives unless the excluded key is present
		{"notequal: excluded key present", match(0, rule64), enabled, defaultMatch, false},
		{"notequal: key absent", nil, enabled, defaultMatch, true},
		// filter not enabled for the rule => unaffected (mask keeps it)
		{"filter disabled for rule", nil, []uint64{0, 0}, []uint64{0, 0}, true},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			// word 0 = all set (kernel-owned, must be untouched); word 1 = rule 64 candidate.
			bitmap := []uint64{^uint64(0), rule64}
			applyOverflowScopeFilter(bitmap, c.bitmaps, c.enabled, c.missing)

			assert.Equal(t, ^uint64(0), bitmap[0], "word 0 (kernel-owned) must not be touched")
			got := bitmap[1]&rule64 != 0
			assert.Equalf(t, c.wantRule, got, "rule 64 survival; word1=%#x", bitmap[1])
		})
	}
}

func TestOverflowBitmapLookups(t *testing.T) {
	t.Parallel()

	// nil maps / absent keys => nil (key-missing behavior downstream)
	assert.Nil(t, u64Bitmaps(nil, 5))
	assert.Nil(t, strBitmaps(nil, "x"))

	u := map[uint64][]policy.RuleBitmap{7: {{EqualsInRules: 1}}}
	assert.Nil(t, u64Bitmaps(u, 8))    // absent key
	assert.NotNil(t, u64Bitmaps(u, 7)) // present
	s := map[string][]policy.RuleBitmap{"a": {{KeyUsedInRules: 2}}}
	assert.Nil(t, strBitmaps(s, "b"))
	assert.NotNil(t, strBitmaps(s, "a"))
}
