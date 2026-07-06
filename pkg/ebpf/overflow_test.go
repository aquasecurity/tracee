package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/filters"
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

// TestBinaryBitmaps verifies the binary lookup mirrors the kernel's double lookup: the path-only key
// ({MntNS: 0, Path}, "any namespace") is tried first, and only when it is absent does the namespaced
// {MntNS, Path} key apply.
func TestBinaryBitmaps(t *testing.T) {
	t.Parallel()

	assert.Nil(t, binaryBitmaps(nil, "/bin/sh", 42))

	// path-only key wins even when a namespaced key also exists
	anyNS := []policy.RuleBitmap{{}, {EqualsInRules: 0b1}}
	nsSpecific := []policy.RuleBitmap{{}, {EqualsInRules: 0b10}}
	m := map[filters.NSBinary][]policy.RuleBitmap{
		{MntNS: 0, Path: "/bin/sh"}:  anyNS,
		{MntNS: 42, Path: "/bin/sh"}: nsSpecific,
	}
	assert.Equal(t, anyNS, binaryBitmaps(m, "/bin/sh", 42), "path-only (any-ns) key must win")

	// with no path-only key, fall back to the namespaced key; a different mnt-ns misses
	m2 := map[filters.NSBinary][]policy.RuleBitmap{{MntNS: 42, Path: "/bin/sh"}: nsSpecific}
	assert.Equal(t, nsSpecific, binaryBitmaps(m2, "/bin/sh", 42))
	assert.Nil(t, binaryBitmaps(m2, "/bin/sh", 7), "different mnt-ns must miss")
	assert.Nil(t, binaryBitmaps(m2, "/other", 42), "different path must miss")
}

// TestOverflowBinaryNarrowing checks the end-to-end bitmap effect of narrowing an overflow rule by an
// executable filter: an overflow rule (bit in word 1) scoped by "=/bin/sh" survives when the event's binary
// is /bin/sh and is cleared when it is not.
func TestOverflowBinaryNarrowing(t *testing.T) {
	t.Parallel()

	// rule 64 (word 1, bit 0) has an equal executable filter; it "uses the key" and equals for /bin/sh.
	binMap := map[filters.NSBinary][]policy.RuleBitmap{
		{MntNS: 0, Path: "/bin/sh"}: {{}, {EqualsInRules: 0b1, KeyUsedInRules: 0b1}},
	}
	// equal filter => match-if-key-missing is 0; the rule is enabled in word 1.
	enabled := []uint64{0, 0b1}
	missing := []uint64{0, 0}

	// matching binary: bit stays set
	bm := []uint64{0, 0b1}
	applyOverflowScopeFilter(bm, binaryBitmaps(binMap, "/bin/sh", 0), enabled, missing)
	assert.Equal(t, uint64(0b1), bm[1], "matching /bin/sh must keep the overflow bit")

	// non-matching binary (key missing => equal filter fails): bit cleared
	bm = []uint64{0, 0b1}
	applyOverflowScopeFilter(bm, binaryBitmaps(binMap, "/usr/bin/evil", 0), enabled, missing)
	assert.Equal(t, uint64(0), bm[1], "non-matching binary must clear the overflow bit")
}
