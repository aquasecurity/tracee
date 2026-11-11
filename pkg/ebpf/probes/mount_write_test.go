package probes

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultProbeGroupMountWriteSymbolAlternatives(t *testing.T) {
	probeGroup, err := NewDefaultProbeGroup(nil, true, true, "")
	require.NoError(t, err)

	type probeTarget struct {
		symbol      string
		probeType   ProbeType
		programName string
	}

	want := map[probeTarget]struct{}{
		{symbol: "mnt_get_write_access", probeType: KProbe, programName: "trace_mnt_get_write_access"}:        {},
		{symbol: "mnt_get_write_access", probeType: KretProbe, programName: "trace_ret_mnt_get_write_access"}: {},
		{symbol: "mnt_want_write", probeType: KProbe, programName: "trace_mnt_get_write_access"}:              {},
		{symbol: "mnt_want_write", probeType: KretProbe, programName: "trace_ret_mnt_get_write_access"}:       {},
		{symbol: "__mnt_want_write", probeType: KProbe, programName: "trace_mnt_get_write_access"}:            {},
		{symbol: "__mnt_want_write", probeType: KretProbe, programName: "trace_ret_mnt_get_write_access"}:     {},
	}
	got := make(map[probeTarget]struct{})

	for _, probe := range probeGroup.probes {
		traceProbe, ok := probe.(*TraceProbe)
		if !ok {
			continue
		}
		target := probeTarget{
			symbol:      traceProbe.GetEventName(),
			probeType:   traceProbe.GetProbeType(),
			programName: traceProbe.GetProgramName(),
		}
		if _, isMountWriteTarget := want[target]; isMountWriteTarget {
			got[target] = struct{}{}
		}
	}

	require.Equal(t, want, got)
}
