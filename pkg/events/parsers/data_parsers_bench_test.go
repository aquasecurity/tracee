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

var optionsAreContainedInArgumentTestTable = []struct {
	rawArgument uint64
	options     []SystemFunctionArgument
}{
	{
		rawArgument: 0x0,
		options:     []SystemFunctionArgument{CLONE_CHILD_CLEARTID},
	},
	{
		rawArgument: PTRACE_TRACEME.Value(),
		options:     []SystemFunctionArgument{PTRACE_TRACEME},
	},
	{
		rawArgument: PTRACE_TRACEME.Value(),
		options:     []SystemFunctionArgument{PTRACE_TRACEME, PTRACE_TRACEME},
	},
	{
		rawArgument: PTRACE_PEEKTEXT.Value(),
		options:     []SystemFunctionArgument{PTRACE_TRACEME},
	},
	{
		rawArgument: PTRACE_TRACEME.Value() | PTRACE_GETSIGMASK.Value(),
		options:     []SystemFunctionArgument{PTRACE_TRACEME, PTRACE_GETSIGMASK},
	},
	{
		rawArgument: BPF_MAP_CREATE.Value(),
		options:     []SystemFunctionArgument{BPF_MAP_CREATE},
	},
	{
		rawArgument: CAP_CHOWN.Value(),
		options:     []SystemFunctionArgument{CAP_CHOWN},
	},
	{
		rawArgument: PTRACE_TRACEME.Value() | PTRACE_GETSIGMASK.Value(),
		options:     []SystemFunctionArgument{PTRACE_TRACEME, PTRACE_GETSIGMASK},
	},
	{
		rawArgument: 0x0,
		options:     []SystemFunctionArgument{PTRACE_TRACEME, PTRACE_GETSIGMASK, PTRACE_ATTACH, PTRACE_DETACH},
	},
}

func BenchmarkOptionsAreContainedInArgument(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for _, tc := range optionsAreContainedInArgumentTestTable {
			_ = OptionsAreContainedInArgument(tc.rawArgument, tc.options...)
		}
	}
}
