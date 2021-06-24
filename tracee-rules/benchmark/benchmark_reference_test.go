// Reference: https://github.com/open-policy-agent/golang-opa-wasm/blob/8041bec28e319aad31fd4632bae46e47727f3ddc/opa/opa_test.go#L154-L216

package benchmark

import (
	"context"
	_ "embed"
	"testing"

	tracee "github.com/aquasecurity/tracee/tracee-ebpf/tracee/external"
	opawasm "github.com/open-policy-agent/golang-opa-wasm/opa"
	oparego "github.com/open-policy-agent/opa/rego"
)

var (
	//go:embed signature/wasm/aio.rego
	aioRego string

	simpleRego = `package p
a = true`
)

func BenchmarkWasm_SimpleRule(b *testing.B) {
	policy := compileRegoToWasm(simpleRego, "data.p.a = x")
	opa, _ := opawasm.New().
		WithPolicyBytes(policy).
		//WithMemoryLimits(131070, 2*131070). // TODO: For some reason unlimited memory slows down the eval_ctx_new().
		//WithPoolSize(1).
		Init()

	ctx := context.Background()
	var input interface{} = make(map[string]interface{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := opa.Eval(ctx, &input); err != nil {
			panic(err)
		}
	}
}

func BenchmarkRegoGoLibrary_SimpleRule(b *testing.B) {
	pq := compileRego(simpleRego, "data.p.a = x")
	input := make(map[string]interface{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pq.Eval(context.Background(), oparego.EvalInput(input)); err != nil {
			panic(err)
		}
	}
}

func BenchmarkWasm_RealRule(b *testing.B) {
	policy := compileRegoToWasm(aioRego, "data.tracee.aio.tracee_match = x")
	opa, _ := opawasm.New().
		WithPolicyBytes(policy).
		//WithMemoryLimits(131070, 2*131070). // TODO: For some reason unlimited memory slows down the eval_ctx_new().
		//WithPoolSize(1).
		Init()

	ctx := context.Background()
	var input interface{} = tracee.Event{
		Timestamp:           6123.321183,
		ProcessID:           1,
		ThreadID:            1,
		ParentProcessID:     3788,
		HostProcessID:       3217,
		HostThreadID:        3217,
		HostParentProcessID: 3788,
		UserID:              0,
		MountNS:             2983424533,
		PIDNS:               2983424536,
		ProcessName:         "injector",
		HostName:            "234134134ab",
		EventID:             328,
		EventName:           "ptrace",
		ArgsNum:             2,
		ReturnValue:         0,
		Args: []tracee.Argument{
			{
				ArgMeta: tracee.ArgMeta{
					Name: "request",
				},
				Value: "PTRACE_POKETEXT",
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := opa.Eval(ctx, &input); err != nil {
			panic(err)
		}
	}
}

func BenchmarkRegoGoLibrary_RealRule(b *testing.B) {
	pq := compileRego(aioRego, "data.tracee.aio.tracee_match = x")
	var input interface{} = tracee.Event{
		Timestamp:           6123.321183,
		ProcessID:           1,
		ThreadID:            1,
		ParentProcessID:     3788,
		HostProcessID:       3217,
		HostThreadID:        3217,
		HostParentProcessID: 3788,
		UserID:              0,
		MountNS:             2983424533,
		PIDNS:               2983424536,
		ProcessName:         "injector",
		HostName:            "234134134ab",
		EventID:             328,
		EventName:           "ptrace",
		ArgsNum:             2,
		ReturnValue:         0,
		Args: []tracee.Argument{
			{
				ArgMeta: tracee.ArgMeta{
					Name: "request",
				},
				Value: "PTRACE_POKETEXT",
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pq.Eval(context.Background(), oparego.EvalInput(input)); err != nil {
			panic(err)
		}
	}
}

func compileRegoToWasm(policy string, query string) []byte {
	module := policy
	cr, err := oparego.New(
		oparego.Query(query),
		oparego.Module("module.rego", module),
	).Compile(context.Background(), oparego.CompilePartial(false))
	//).Compile(context.Background(), oparego.CompilePartial(true)) // Panics
	if err != nil {
		panic(err)
	}

	return cr.Bytes
}

func compileRego(module string, query string) oparego.PreparedEvalQuery {
	rego := oparego.New(
		oparego.Query(query),
		oparego.Module("module.rego", module),
	)
	pq, err := rego.PrepareForEval(context.Background())
	if err != nil {
		panic(err)
	}

	return pq
}
