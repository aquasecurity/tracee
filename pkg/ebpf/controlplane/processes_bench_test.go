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

func Benchmark_procTreeExecProcessor(b *testing.B) {
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
		{ArgMeta: trace.ArgMeta{Name: "task_hash"}, Value: uint32(1)},
		{ArgMeta: trace.ArgMeta{Name: "parent_hash"}, Value: uint32(1)},
		{ArgMeta: trace.ArgMeta{Name: "leader_hash"}, Value: uint32(1)},
		{ArgMeta: trace.ArgMeta{Name: "cmdpath"}, Value: "/bin/bash"},
		{ArgMeta: trace.ArgMeta{Name: "pathname"}, Value: "/bin/bash"},
		{ArgMeta: trace.ArgMeta{Name: "dev"}, Value: uint32(1)},
		{ArgMeta: trace.ArgMeta{Name: "inode"}, Value: uint64(1)},
		{ArgMeta: trace.ArgMeta{Name: "ctime"}, Value: uint64(1)},
		{ArgMeta: trace.ArgMeta{Name: "inode_mode"}, Value: uint16(1)},
		// {ArgMeta: trace.ArgMeta{Name: "interpreter_pathname"}, Value: "/lib64/ld-linux-x86-64.so.2"},
		// {ArgMeta: trace.ArgMeta{Name: "interpreter_dev"}, Value: uint32(1)},
		// {ArgMeta: trace.ArgMeta{Name: "interpreter_inode"}, Value: uint64(1)},
		// {ArgMeta: trace.ArgMeta{Name: "interpreter_ctime"}, Value: uint64(1)},
		{ArgMeta: trace.ArgMeta{Name: "interp"}, Value: "/lib64/ld-linux-x86-64.so.2"},
		{ArgMeta: trace.ArgMeta{Name: "stdin_type"}, Value: uint16(1)},
		{ArgMeta: trace.ArgMeta{Name: "stdin_path"}, Value: "/dev/null"},
		{ArgMeta: trace.ArgMeta{Name: "invoked_from_kernel"}, Value: int32(1)},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ctrl.procTreeExecProcessor(args)
	}
}

func Benchmark_procTreeExitProcessor(b *testing.B) {
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
		{ArgMeta: trace.ArgMeta{Name: "task_hash"}, Value: uint32(1)},
		{ArgMeta: trace.ArgMeta{Name: "parent_hash"}, Value: uint32(1)},
		{ArgMeta: trace.ArgMeta{Name: "leader_hash"}, Value: uint32(1)},
		{ArgMeta: trace.ArgMeta{Name: "exit_code"}, Value: int64(1)},
		{ArgMeta: trace.ArgMeta{Name: "process_group_exit"}, Value: true},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ctrl.procTreeExitProcessor(args)
	}
}
