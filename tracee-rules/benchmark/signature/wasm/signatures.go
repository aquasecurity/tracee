package wasm

import (
	"context"
	_ "embed"
	"fmt"
	"regexp"
	"strings"

	"github.com/open-policy-agent/opa/ast"

	"github.com/open-policy-agent/opa/rego"

	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/open-policy-agent/golang-opa-wasm/opa"
)

var (
	//go:embed helpers.rego
	helpersRego string

	//go:embed anti_debugging_ptraceme.rego
	antiDebuggingPtracemeRego string

	//go:embed code_injection.rego
	codeInjectionRego string
)

func compileRegoToWasm(regoCodes []string) []byte {
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

	var err error
	compiledRego, err = ast.CompileModules(regoMap)
	if err != nil {
		panic(err)
	}

	cr, err := rego.New(
		rego.Compiler(compiledRego),
		rego.Query(fmt.Sprintf("data.%s.tracee_match", pkgName)),
	).Compile(context.Background(), rego.CompilePartial(false))
	if err != nil {
		panic(err)
	}
	return cr.Bytes
}

func NewCodeInjectionSignature() (types.Signature, error) {
	return NewSignature(types.SignatureMetadata{
		ID: "TRC_WASM_CODE_INJECTION",
	}, []types.SignatureEventSelector{
		{Source: "tracee", Name: "ptrace"},
		{Source: "tracee", Name: "open"},
		{Source: "tracee", Name: "openat"},
		{Source: "tracee", Name: "execve"},
	}, []string{codeInjectionRego, helpersRego})
}

func NewAntiDebuggingSignature() (types.Signature, error) {
	return NewSignature(types.SignatureMetadata{
		ID: "TRC_WASM_ANTI_DEBUGGING",
	}, []types.SignatureEventSelector{
		{Source: "tracee", Name: "ptrace"},
	}, []string{antiDebuggingPtracemeRego, helpersRego})
}

type signature struct {
	metadata types.SignatureMetadata
	selector []types.SignatureEventSelector
	cb       types.SignatureHandler
	rego     *opa.OPA
}

func NewSignature(metadata types.SignatureMetadata, selector []types.SignatureEventSelector, regoCodes []string) (types.Signature, error) {
	rego, err := opa.New().WithPolicyBytes(compileRegoToWasm(regoCodes)).Init()
	if err != nil {
		return nil, err
	}
	return &signature{
		metadata: metadata,
		selector: selector,
		rego:     rego,
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
	results, err := s.rego.Eval(context.Background(), &input)
	if err != nil {
		return err
	}
	if results == nil {
		return fmt.Errorf("no match")
	}

	r, ok := results.Result.([]interface{})
	if !ok || len(r) == 0 {
		return nil
	}

	if len(r) > 0 && r[0] != nil {
		switch v := r[0].(type) {
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
