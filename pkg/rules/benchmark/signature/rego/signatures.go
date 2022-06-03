package rego

import (
	_ "embed"

	"github.com/aquasecurity/tracee/pkg/rules/regosig"
	"github.com/aquasecurity/tracee/types/detect"
)

var (
	//go:embed helpers.rego
	helpersRego string

	//go:embed anti_debugging_ptraceme.rego
	antiDebuggingPtracemeRego string

	//go:embed code_injection.rego
	codeInjectionRego string
)

func NewCodeInjectionSignature() (detect.Signature, error) {
	return regosig.NewRegoSignature(false, codeInjectionRego, helpersRego)
}

func NewAntiDebuggingSignature() (detect.Signature, error) {
	return regosig.NewRegoSignature(false, antiDebuggingPtracemeRego, helpersRego)
}
