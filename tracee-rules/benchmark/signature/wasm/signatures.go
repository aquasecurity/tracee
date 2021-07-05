package wasm

import (
	_ "embed"

	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

var (
	//go:embed helpers.rego
	helpersRego string

	//go:embed anti_debugging_ptraceme.rego
	antiDebuggingPtracemeRego string

	//go:embed code_injection.rego
	codeInjectionRego string
)

func compileRego(regoCodes []string) (*ast.Compiler, string) {
	re := regexp.MustCompile(`package\s.*`) // TODO: DRY

	var pkgName string
	regoMap := make(map[string]string)
	var compiledRego *ast.Compiler

	for _, regoCode := range regoCodes {
		regoModuleName := strings.Split(re.FindString(regoCode), " ")[1]
		if !strings.Contains(regoCode, "package tracee.helpers") {
			pkgName = regoModuleName
		}
		regoMap[regoModuleName] = regoCode
	}

	compiledRego, err := ast.CompileModules(regoMap)
	if err != nil {
		panic(err)
	}
	return compiledRego, pkgName
}

func NewCodeInjectionSignature() (types.Signature, error) {
	return NewSignature(types.SignatureMetadata{
		ID:   "TRC_WASM_CODE_INJECTION",
		Name: "Code Injection WASM",
	}, []types.SignatureEventSelector{
		{Source: "tracee", Name: "ptrace"},
		{Source: "tracee", Name: "open"},
		{Source: "tracee", Name: "openat"},
		{Source: "tracee", Name: "execve"},
	}, []string{codeInjectionRego, helpersRego})
}

func NewAntiDebuggingSignature() (types.Signature, error) {
	return NewSignature(types.SignatureMetadata{
		ID:   "TRC_WASM_ANTI_DEBUGGING",
		Name: "Anti Debugging WASM",
	}, []types.SignatureEventSelector{
		{Source: "tracee", Name: "ptrace"},
	}, []string{antiDebuggingPtracemeRego, helpersRego})
}

type signature struct {
	metadata types.SignatureMetadata
	selector []types.SignatureEventSelector
	cb       types.SignatureHandler
	rego     *rego.Rego
	pq       rego.PreparedEvalQuery
}

func NewSignature(metadata types.SignatureMetadata, selector []types.SignatureEventSelector, regoCodes []string) (types.Signature, error) {
	compiledRego, pkgName := compileRego(regoCodes)
	rego := rego.New(
		rego.Compiler(compiledRego),
		rego.Query(fmt.Sprintf("data.%s.tracee_match = x", pkgName)),
		rego.Target("wasm"),
	)
	pq, err := rego.PrepareForEval(context.Background())
	if err != nil {
		return nil, err
	}
	return &signature{
		metadata: metadata,
		selector: selector,
		rego:     rego,
		pq:       pq,
	}, nil
}

func (s *signature) Init(cb types.SignatureHandler) error {
	s.cb = cb
	return nil
}

func (s *signature) GetMetadata() (types.SignatureMetadata, error) {
	return s.metadata, nil
}

func (s *signature) GetSelectedEvents() ([]types.SignatureEventSelector, error) {
	return s.selector, nil
}

func (s *signature) OnEvent(event types.Event) error {
	var input interface{} = event
	results, err := s.pq.Eval(context.Background(), rego.EvalInput(input))
	if err != nil {
		return err
	}

	if len(results) > 0 && len(results[0].Expressions) > 0 && results[0].Expressions[0].Value != nil {
		switch v := results[0].Expressions[0].Value.(type) {
		case bool:
			if v {
				s.cb(types.Finding{
					Data:        nil,
					Context:     event,
					SigMetadata: s.metadata,
				})
			}
		case map[string]interface{}:
			s.cb(types.Finding{
				Data:        v,
				Context:     event,
				SigMetadata: s.metadata,
			})
		}
	}

	return nil
}

func (s *signature) OnSignal(_ types.Signal) error {
	// noop
	return nil
}
func (s *signature) Close() {}
