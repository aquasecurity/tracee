package parsers

import "testing"

var parseMmapProtBenchTestArgs = []struct {
	rawValue uint64
}{
	{
		rawValue: PROT_NONE.Value(),
	},
	{
		rawValue: PROT_EXEC.Value(),
	},
	{
		rawValue: PROT_EXEC.Value() | PROT_READ.Value(),
	},
}

func BenchmarkParseMmapProt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for _, tt := range parseMmapProtBenchTestArgs {
			ParseMmapProt(tt.rawValue)
		}
	}
}

var parseCloneFlagsBenchTestArgs = []struct {
	rawArgument uint64
}{
	{
		rawArgument: CLONE_VM.Value(),
	},
	{
		rawArgument: CLONE_FS.Value(),
	},
	{
		rawArgument: CLONE_VM.Value() | CLONE_FS.Value(),
	},
	{
		rawArgument: CLONE_VM.Value() | CLONE_FS.Value() | CLONE_FILES.Value(),
	},
	{
		rawArgument: CLONE_VM.Value() | CLONE_FILES.Value() | CLONE_THREAD.Value(),
	},
	{
		rawArgument: CLONE_VM.Value() | CLONE_FS.Value() | CLONE_FILES.Value() | CLONE_SIGHAND.Value(),
	},
	{
		rawArgument: CLONE_VM.Value() | CLONE_FS.Value() | CLONE_FILES.Value() | CLONE_SIGHAND.Value() | CLONE_PTRACE.Value(),
	},
	{
		rawArgument: CLONE_VM.Value() | CLONE_FS.Value() | CLONE_FILES.Value() | CLONE_SIGHAND.Value() | CLONE_PTRACE.Value() | CLONE_VFORK.Value(),
	},
}

func BenchmarkParseCloneFlags(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for _, tt := range parseCloneFlagsBenchTestArgs {
			_, _ = ParseCloneFlags(tt.rawArgument)
		}
	}
}

var optionsAreContainedInArgumentTestTable = []struct {
	rawArgument uint64
	options     []uint64
}{
	{
		rawArgument: 0x0,
		options:     []uint64{CLONE_CHILD_CLEARTID.Value()},
	},
	{
		rawArgument: PTRACE_TRACEME.Value(),
		options:     []uint64{PTRACE_TRACEME.Value()},
	},
	{
		rawArgument: PTRACE_TRACEME.Value(),
		options:     []uint64{PTRACE_TRACEME.Value(), PTRACE_ATTACH.Value()},
	},
	{
		rawArgument: PTRACE_PEEKTEXT.Value(),
		options:     []uint64{PTRACE_TRACEME.Value()},
	},
	{
		rawArgument: PTRACE_TRACEME.Value() | PTRACE_GETSIGMASK.Value(),
		options:     []uint64{PTRACE_TRACEME.Value(), PTRACE_GETSIGMASK.Value()},
	},
	{
		rawArgument: BPF_MAP_CREATE.Value(),
		options:     []uint64{BPF_MAP_CREATE.Value()},
	},
	{
		rawArgument: CAP_CHOWN.Value(),
		options:     []uint64{CAP_CHOWN.Value()},
	},
	{
		rawArgument: PTRACE_TRACEME.Value() | PTRACE_GETSIGMASK.Value(),
		options:     []uint64{PTRACE_TRACEME.Value(), PTRACE_GETSIGMASK.Value()},
	},
	{
		rawArgument: 0x0,
		options:     []uint64{PTRACE_TRACEME.Value(), PTRACE_GETSIGMASK.Value(), PTRACE_ATTACH.Value(), PTRACE_DETACH.Value()},
	},
}

func Benchmark_optionsAreContainedInArgument(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for _, tc := range optionsAreContainedInArgumentTestTable {
			_ = optionsAreContainedInArgument(tc.rawArgument, tc.options...)
		}
	}
}

func Benchmark_optionsAreContainedInArgumentWithOnlyOne(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for _, tc := range optionsAreContainedInArgumentTestTable {
			_ = optionsAreContainedInArgument(tc.rawArgument, tc.options[0])
		}
	}
}

func Benchmark_optionIsContainedInArgument(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for _, tc := range optionsAreContainedInArgumentTestTable {
			_ = optionIsContainedInArgument(tc.rawArgument, tc.options[0])
		}
	}
}
