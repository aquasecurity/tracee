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

type CodeInjectionWASMSignature struct {
	types.Signature
	rego *opa.OPA
	cb   types.SignatureHandler
}

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

	//fmt.Println(pkgName)

	cr, err := rego.New(
		rego.Compiler(compiledRego),
		rego.Query(fmt.Sprintf("data.%s.tracee_match", pkgName)),
	).Compile(context.Background(), rego.CompilePartial(false))
	if err != nil {
		panic(err)
	}
	return cr.Bytes
}

func (w *CodeInjectionWASMSignature) Init(cb types.SignatureHandler) error {
	w.cb = cb

	var err error
	w.rego, err = opa.New().WithPolicyBytes(compileRegoToWasm([]string{codeInjectionRego, helpersRego})).Init()
	if err != nil {
		return err
	}
	return nil
}

func (w *CodeInjectionWASMSignature) OnEvent(event types.Event) error {
	var input interface{} = event
	results, err := w.rego.Eval(context.Background(), &input)
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
				w.cb(types.Finding{
					Data:    nil,
					Context: event,
					//SigMetadata: w.metadata,
				})
			}
		case map[string]interface{}:
			w.cb(types.Finding{
				Data:    v,
				Context: event,
				//SigMetadata: w.metadata,
			})
		}
	}

	return nil
}

func (w CodeInjectionWASMSignature) GetMetadata() (types.SignatureMetadata, error) {
	return types.SignatureMetadata{
		ID: "TRC_WASM_CODE_INJECTION",
	}, nil
}

func (w CodeInjectionWASMSignature) GetSelectedEvents() ([]types.SignatureEventSelector, error) {
	return []types.SignatureEventSelector{
		{Source: "tracee", Name: "ptrace"},
		{Source: "tracee", Name: "open"},
		{Source: "tracee", Name: "openat"},
		{Source: "tracee", Name: "execve"},
	}, nil
}

func NewCodeInjectionSignature() (types.Signature, error) {
	return &CodeInjectionWASMSignature{}, nil
}

type AntiDebuggingWASMSignature struct {
	types.Signature
	cb   types.SignatureHandler
	rego *opa.OPA
}

func (w *AntiDebuggingWASMSignature) Init(cb types.SignatureHandler) error {
	w.cb = cb
	var err error
	w.rego, err = opa.New().WithPolicyBytes(compileRegoToWasm([]string{antiDebuggingPtracemeRego, helpersRego})).Init()
	if err != nil {
		return err
	}
	return nil
}

func (w *AntiDebuggingWASMSignature) OnEvent(event types.Event) error {
	var input interface{} = event
	results, err := w.rego.Eval(context.Background(), &input)
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
				w.cb(types.Finding{
					Data:    nil,
					Context: event,
					//SigMetadata: w.metadata,
				})
			}
		case map[string]interface{}:
			w.cb(types.Finding{
				Data:    v,
				Context: event,
				//SigMetadata: w.metadata,
			})
		}
	}

	return nil
}

func (w AntiDebuggingWASMSignature) GetMetadata() (types.SignatureMetadata, error) {
	return types.SignatureMetadata{
		ID: "TRC_WASM_ANTI_DEBUGGING",
	}, nil
}

func (w AntiDebuggingWASMSignature) GetSelectedEvents() ([]types.SignatureEventSelector, error) {
	return []types.SignatureEventSelector{
		{Source: "tracee", Name: "ptrace"},
	}, nil
}

func NewAntiDebuggingSignature() (types.Signature, error) {
	return &AntiDebuggingWASMSignature{}, nil
}
