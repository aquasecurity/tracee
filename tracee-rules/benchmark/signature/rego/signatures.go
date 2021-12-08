package rego

import (
	_ "embed"

	"github.com/aquasecurity/tracee/signatures/rego/regosig"

	"github.com/open-policy-agent/opa/compile"

	"github.com/aquasecurity/tracee/tracee-rules/types"
)

var (
	//go:embed helpers.rego
	helpersRego string

	//go:embed anti_debugging_ptraceme.rego
	antiDebuggingPtracemeRego string

	//go:embed code_injection.rego
	codeInjectionRego string
)

func NewCodeInjectionSignature() (types.Signature, error) {
	return regosig.NewRegoSignature(compile.TargetRego, false, codeInjectionRego, helpersRego)
}

func NewAntiDebuggingSignature() (types.Signature, error) {
	return regosig.NewRegoSignature(compile.TargetRego, false, antiDebuggingPtracemeRego, helpersRego)
}
