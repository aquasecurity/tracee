package events

import (
	"sync"
	"testing"

	"github.com/aquasecurity/tracee/types/trace"
)

var events = []*trace.Event{
	{
		EventID: int(MemProtAlert),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "alert"}, Value: uint32(0)},
			{ArgMeta: trace.ArgMeta{Name: "prot"}, Value: int32(0)},
			{ArgMeta: trace.ArgMeta{Name: "prev_prot"}, Value: int32(0)},
		},
	},
	{
		EventID: int(SysEnter),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "syscall"}, Value: int32(0)},
		},
	},
	{
		EventID: int(SysExit),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "ret"}, Value: int64(0)},
		},
	},
	{
		EventID: int(CapCapable),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "cap"}, Value: int32(0)},
		},
	},
	{
		EventID: int(SecurityMmapFile),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "prot"}, Value: uint64(0)},
		},
	},
	{
		EventID: int(DoMmap),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "prot"}, Value: uint64(0)},
		},
	},
	{
		EventID: int(Mmap),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "prot"}, Value: uint64(0)},
		},
	},
	{
		EventID: int(Mprotect),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "prot"}, Value: uint64(0)},
		},
	},
	{
		EventID: int(PkeyMprotect),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "prot"}, Value: uint64(0)},
		},
	},
	{
		EventID: int(SecurityFileMprotect),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "prot"}, Value: uint64(0)},
			{ArgMeta: trace.ArgMeta{Name: "prev_prot"}, Value: int32(0)},
		},
	},
	{
		EventID: int(Ptrace),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "request"}, Value: int64(0)},
		},
	},
	{
		EventID: int(Prctl),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "option"}, Value: int32(0)},
		},
	},
	{
		EventID: int(Socketcall),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "call"}, Value: int32(0)},
		},
	},
	{
		EventID: int(Socket),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "domain"}, Value: int32(0)},
			{ArgMeta: trace.ArgMeta{Name: "type"}, Value: int32(0)},
		},
	},
	{
		EventID: int(SecuritySocketCreate),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "family"}, Value: int32(0)},
			{ArgMeta: trace.ArgMeta{Name: "type"}, Value: int32(0)},
		},
	},
	{
		EventID: int(SecuritySocketConnect),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "family"}, Value: int32(0)},
			{ArgMeta: trace.ArgMeta{Name: "type"}, Value: int32(0)},
		},
	},
	{
		EventID: int(Access),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "mode"}, Value: int32(0)},
		},
	},
	{
		EventID: int(Faccessat),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "mode"}, Value: int32(0)},
		},
	},
	{
		EventID: int(Execveat),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "flags"}, Value: int32(0)},
		},
	},
	{
		EventID: int(Open),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "flags"}, Value: int32(0)},
		},
	},
	{
		EventID: int(Openat),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "flags"}, Value: int32(0)},
		},
	},
	{
		EventID: int(SecurityFileOpen),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "flags"}, Value: int32(0)},
		},
	},
	{
		EventID: int(Mknod),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "mode"}, Value: uint32(0)},
		},
	},
	{
		EventID: int(Mknodat),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "mode"}, Value: uint32(0)},
		},
	},
	{
		EventID: int(Chmod),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "mode"}, Value: uint32(0)},
		},
	},
	{
		EventID: int(Fchmod),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "mode"}, Value: uint32(0)},
		},
	},
	{
		EventID: int(Fchmodat),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "mode"}, Value: uint32(0)},
		},
	},
	{
		EventID: int(SecurityInodeMknod),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "mode"}, Value: uint32(0)},
		},
	},
	{
		EventID: int(Clone),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "flags"}, Value: uint64(0)},
		},
	},
	{
		EventID: int(Bpf),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "cmd"}, Value: int32(0)},
		},
	},
	{
		EventID: int(SecurityBPF),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "cmd"}, Value: int32(0)},
		},
	},
	{
		EventID: int(SecurityKernelReadFile),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "type"}, Value: trace.KernelReadType(0)},
		},
	},
	{
		EventID: int(SecurityPostReadFile),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "type"}, Value: trace.KernelReadType(0)},
		},
	},
	{
		EventID: int(SchedProcessExec),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "stdin_type"}, Value: uint16(0)},
		},
	},
	{
		EventID: int(DirtyPipeSplice),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "in_file_type"}, Value: uint16(0)},
		},
	},
	{
		EventID: int(SecuritySocketSetsockopt),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "level"}, Value: int32(0)},
			{ArgMeta: trace.ArgMeta{Name: "optname"}, Value: int32(0)},
		},
	},
	{
		EventID: int(Setsockopt),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "level"}, Value: int32(0)},
			{ArgMeta: trace.ArgMeta{Name: "optname"}, Value: int32(0)},
		},
	},
	{
		EventID: int(Getsockopt),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "level"}, Value: int32(0)},
			{ArgMeta: trace.ArgMeta{Name: "optname"}, Value: int32(0)},
		},
	},
	{
		EventID: int(BpfAttach),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "prog_type"}, Value: int32(0)},
			{ArgMeta: trace.ArgMeta{Name: "prog_helpers"}, Value: []uint64{}},
			{ArgMeta: trace.ArgMeta{Name: "attach_type"}, Value: int32(0)},
		},
	},
	{
		EventID: int(SecurityBpfProg),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "type"}, Value: int32(0)},
			{ArgMeta: trace.ArgMeta{Name: "helpers"}, Value: []uint64{}},
		},
	},
	{
		EventID: int(SecurityPathNotify),
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "mask"}, Value: uint64(0)},
			{ArgMeta: trace.ArgMeta{Name: "obj_type"}, Value: uint32(0)},
		},
	},
}

func BenchmarkParseArgs(b *testing.B) {
	for n := 0; n < b.N; n++ {
		for _, event := range events {
			err := ParseArgs(event)
			if err != nil {
				b.Errorf("Error parsing args: %v", err)
			}
		}
	}
}

func BenchmarkParseArgs_Uintptr(b *testing.B) {
	for n := 0; n < b.N; n++ {
		ptraceEvent := &trace.Event{
			EventID: int(Ptrace),
			Args: []trace.Argument{
				{ArgMeta: trace.ArgMeta{Name: "request"}, Value: int64(0)},
				{ArgMeta: trace.ArgMeta{Name: "pid"}, Value: int32(0)},
				{ArgMeta: trace.ArgMeta{Name: "addr"}, Value: ^uintptr(0)},
				{ArgMeta: trace.ArgMeta{Name: "data"}, Value: ^uintptr(0)},
			},
		}

		err := ParseArgs(ptraceEvent)
		if err != nil {
			b.Errorf("Error parsing args: %v", err)
		}
	}
}

func Benchmark_parseSyscall(b *testing.B) {
	for n := 0; n < b.N; n++ {
		wg := sync.WaitGroup{}
		wg.Add(10)

		for i := 0; i < 10; i++ {
			syscallArg := &trace.Argument{ArgMeta: trace.ArgMeta{Name: "syscall"}, Value: int32(0)}
			go func() {
				defer wg.Done()
				parseSyscall(syscallArg, 0)
			}()
		}

		wg.Wait()
	}
}
