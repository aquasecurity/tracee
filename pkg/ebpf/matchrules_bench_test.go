package ebpf

import (
	"testing"

	"github.com/aquasecurity/tracee/pkg/events"
)

// BenchmarkMatchOverflowRules covers the userland overflow scope-matching hot path added by the
// rules model (>64 rules on one event). The port review noted this wiring had no benchmark; it
// runs per kernel-origin event once an event carries overflow rules.
func BenchmarkMatchOverflowRules(b *testing.B) {
	pm := buildManagerSelecting(b, 70) // rules 0..69 => hasOverflow
	tr := &Tracee{policyManager: pm}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev := &events.PipelineEvent{EventID: ovfEvent, MatchedRulesBitmap: []uint64{0}}
		tr.matchOverflowRules(ev)
	}
}

// BenchmarkGetAllRulesBitmap covers the seed the net-event decode path calls per packet
// (the highest-rate events in the system). O1 caches the bitmap on EventRules so this is a
// single copy rather than a rule-map iteration; the benchmark guards that it stays cheap.
func BenchmarkGetAllRulesBitmap(b *testing.B) {
	pm := buildManagerSelecting(b, 70)
	snap := pm.LoadSnapshot()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = snap.GetAllRulesBitmap(ovfEvent)
	}
}
