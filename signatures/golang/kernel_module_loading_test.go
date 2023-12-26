package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestKernelModuleLoading(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		Name     string
		Events   []trace.Event
		Findings map[string]*detect.Finding
	}{
		{
			Name: "should trigger detection - init_module",
			Events: []trace.Event{
				{
					EventName: "init_module",
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1017": {
					Data: nil,
					Event: trace.Event{
						EventName: "init_module",
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1017",
						Version:     "1",
						Name:        "Kernel module loading detected",
						EventName:   "kernel_module_loading",
						Description: "Loading of a kernel module was detected. Kernel modules are binaries meant to run in the kernel. Adversaries may try and load kernel modules to extend their capabilities and avoid detection by running in the kernel and not user space.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "persistence",
							"Technique":            "Kernel Modules and Extensions",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--a1b52199-c8c5-438a-9ded-656f1d0888c6",
							"external_id":          "T1547.006",
						},
					},
				},
			},
		},
		{
			Name: "should trigger detection - security_kernel_read_file",
			Events: []trace.Event{
				{
					EventName: "security_kernel_read_file",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "type",
							},
							Value: interface{}("kernel-module"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1017": {
					Data: nil,
					Event: trace.Event{
						EventName: "security_kernel_read_file",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "type",
								},
								Value: interface{}("kernel-module"),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1017",
						Version:     "1",
						Name:        "Kernel module loading detected",
						EventName:   "kernel_module_loading",
						Description: "Loading of a kernel module was detected. Kernel modules are binaries meant to run in the kernel. Adversaries may try and load kernel modules to extend their capabilities and avoid detection by running in the kernel and not user space.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "persistence",
							"Technique":            "Kernel Modules and Extensions",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--a1b52199-c8c5-438a-9ded-656f1d0888c6",
							"external_id":          "T1547.006",
						},
					},
				},
			},
		},
		{
			Name: "should not trigger detection - security_kernel_read_file wrong type",
			Events: []trace.Event{
				{
					EventName: "security_kernel_read_file",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "type",
							},
							Value: interface{}("firmware"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{},
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			holder := signaturestest.FindingsHolder{}
			sig := KernelModuleLoading{}
			sig.Init(detect.SignatureContext{Callback: holder.OnFinding})

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
