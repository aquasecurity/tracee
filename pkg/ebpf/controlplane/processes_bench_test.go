package controlplane

import (
	"context"
	"testing"

	"github.com/aquasecurity/tracee/pkg/proctree"
	"github.com/aquasecurity/tracee/types/trace"
)

func Benchmark_procTreeForkProcessor(b *testing.B) {
	ctrl := &Controller{}
	ctrl.processTree, _ = proctree.NewProcessTree(
		context.Background(),
		proctree.ProcTreeConfig{
			Source:           proctree.SourceBoth,
			ProcessCacheSize: proctree.DefaultProcessCacheSize,
			ThreadCacheSize:  proctree.DefaultThreadCacheSize,
		},
	)

	args := []trace.Argument{
		{ArgMeta: trace.ArgMeta{Name: "timestamp"}, Value: uint64(1)},
		{ArgMeta: trace.ArgMeta{Name: "parent_process_tid"}, Value: int32(1)},
		{ArgMeta: trace.ArgMeta{Name: "parent_process_ns_tid"}, Value: int32(1)},
		{ArgMeta: trace.ArgMeta{Name: "parent_process_pid"}, Value: int32(1)},
		{ArgMeta: trace.ArgMeta{Name: "parent_process_ns_pid"}, Value: int32(1)},
		{ArgMeta: trace.ArgMeta{Name: "parent_process_start_time"}, Value: uint64(1)},
		{ArgMeta: trace.ArgMeta{Name: "leader_tid"}, Value: int32(1)},
		{ArgMeta: trace.ArgMeta{Name: "leader_ns_tid"}, Value: int32(1)},
		{ArgMeta: trace.ArgMeta{Name: "leader_pid"}, Value: int32(1)},
		{ArgMeta: trace.ArgMeta{Name: "leader_ns_pid"}, Value: int32(1)},
		{ArgMeta: trace.ArgMeta{Name: "leader_start_time"}, Value: uint64(1)},
		{ArgMeta: trace.ArgMeta{Name: "child_tid"}, Value: int32(2)},
		{ArgMeta: trace.ArgMeta{Name: "child_ns_tid"}, Value: int32(2)},
		{ArgMeta: trace.ArgMeta{Name: "child_pid"}, Value: int32(2)},
		{ArgMeta: trace.ArgMeta{Name: "child_ns_pid"}, Value: int32(2)},
		{ArgMeta: trace.ArgMeta{Name: "start_time"}, Value: uint64(2)},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ctrl.procTreeForkProcessor(args)
	}
}
