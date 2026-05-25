package events

import (
	"testing"
)

// BenchmarkConvertToProto measures one-shot conversion cost (each call acquires
// a fresh slab from the pool but the previous slab is not returned, so this
// approximates the cost from a caller's perspective — alloc per event).
func BenchmarkConvertToProto(b *testing.B) {
	e := buildSyntheticTraceEvent()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ConvertToProto(e)
	}
}

// BenchmarkPipelineEventToProto mirrors the pipeline's lifecycle: convert,
// then Reset to return the slab to the pool. After warm-up the slab is
// recycled with zero new allocations for the pooled fields.
func BenchmarkPipelineEventToProto(b *testing.B) {
	e := buildSyntheticTraceEvent()
	pe := NewPipelineEvent(e)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pe.ToProto()
		pe.Reset()
		pe.Event = e // re-arm for the next iteration
	}
}
