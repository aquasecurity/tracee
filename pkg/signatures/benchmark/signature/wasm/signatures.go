package wasm

import (
	"context"
	_ "embed"
	"fmt"
	"regexp"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
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

func NewCodeInjectionSignature() (detect.Signature, error) {
	return NewSignature(detect.SignatureMetadata{
		ID:   "TRC_WASM_CODE_INJECTION",
		Name: "Code Injection WASM",
	}, []detect.SignatureEventSelector{
		{Source: "tracee", Name: "ptrace"},
		{Source: "tracee", Name: "open"},
		{Source: "tracee", Name: "openat"},
		{Source: "tracee", Name: "execve"},
	}, []string{codeInjectionRego, helpersRego})
}

func NewAntiDebuggingSignature() (detect.Signature, error) {
	return NewSignature(detect.SignatureMetadata{
		ID:   "TRC_WASM_ANTI_DEBUGGING",
		Name: "Anti Debugging WASM",
	}, []detect.SignatureEventSelector{
		{Source: "tracee", Name: "ptrace"},
	}, []string{antiDebuggingPtracemeRego, helpersRego})
}

type signature struct {
	metadata detect.SignatureMetadata
	selector []detect.SignatureEventSelector
	cb       detect.SignatureHandler
	rego     *rego.Rego
	pq       rego.PreparedEvalQuery
}

func NewSignature(metadata detect.SignatureMetadata, selector []detect.SignatureEventSelector, regoCodes []string) (detect.Signature, error) {
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

func (s *signature) Init(ctx detect.SignatureContext) error {
	s.cb = ctx.Callback
	return nil
}

func (s *signature) GetMetadata() (detect.SignatureMetadata, error) {
	return s.metadata, nil
}

func (s *signature) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return s.selector, nil
}

func (s *signature) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)

	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}
	var input interface{} = ee
	results, err := s.pq.Eval(context.Background(), rego.EvalInput(input))
	if err != nil {
		return err
	}

	if len(results) > 0 && len(results[0].Expressions) > 0 && results[0].Expressions[0].Value != nil {
		switch v := results[0].Expressions[0].Value.(type) {
		case bool:
			if v {
				s.cb(detect.Finding{
					Data:        nil,
					Event:       event,
					SigMetadata: s.metadata,
				})
			}
		case map[string]interface{}:
			s.cb(detect.Finding{
				Data:        v,
				Event:       event,
				SigMetadata: s.metadata,
			})
		}
	}

	return nil
}

func (s *signature) OnSignal(_ detect.Signal) error {
	// noop
	return nil
}
func (s *signature) Close() {}
