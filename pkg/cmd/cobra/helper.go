package cobra

import (
	"strings"

	"github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/policy"
)

func getConfigAndPrinterFromPoliciesFlags(cfg tracee.Config, policyFlags, outputFlags []string) (tracee.Config, printer.EventPrinter, error) {
	policyFiles, err := policy.PoliciesFromPaths(policyFlags)
	if err != nil {
		return cfg, nil, err
	}

	filterMap, err := flags.PrepareFilterMapFromPolicies(policyFiles)
	if err != nil {
		return cfg, nil, err
	}

	policies, err := flags.CreatePolicies(filterMap, true)
	if err != nil {
		return cfg, nil, err
	}
	cfg.Policies = policies

	// we ignore printers passed in the flags if you using policies,
	// though we still need the output options
	// TODO: extract output options from --output flag
	outputFlags = getOutputOptions(outputFlags)
	outputFlags = append(outputFlags, getOutputFlagsFromPolicies(policyFiles)...)

	// Output command line flags
	output, err := flags.PrepareOutput(outputFlags, true)
	if err != nil {
		return cfg, nil, err
	}
	cfg.Output = output.TraceeConfig

	// The policy printer routes the event to the printer specified in the policy,
	// or an the event inside the policy
	p, err := printer.NewPolicyEventPrinter(output.PrinterConfigs, policyFiles, cmd.GetContainerMode(cfg))
	if err != nil {
		return cfg, nil, err
	}

	return cfg, p, err
}

func getConfigAndPrinterFromFilterFlags(cfg tracee.Config, filterFlags, outputFlags []string) (tracee.Config, printer.EventPrinter, error) {
	filterMap, err := flags.PrepareFilterMapFromFlags(filterFlags)
	if err != nil {
		return cfg, nil, err
	}

	policies, err := flags.CreatePolicies(filterMap, true)
	if err != nil {
		return cfg, nil, err
	}

	cfg.Policies = policies

	// Output command line flags
	output, err := flags.PrepareOutput(outputFlags, true)
	if err != nil {
		return cfg, nil, err
	}
	cfg.Output = output.TraceeConfig

	// Create printer
	p, err := printer.NewBroadcast(output.PrinterConfigs, cmd.GetContainerMode(cfg))
	if err != nil {
		return cfg, nil, err
	}

	return cfg, p, err
}

// getOutputOptions returns a slice of output options from the output flags
func getOutputOptions(outputFlags []string) []string {
	options := make([]string, 0)

	for _, f := range outputFlags {
		if strings.HasPrefix(f, "option:") {
			options = append(options, f)
		}
	}

	return options
}

// getOutputFlagsFromPolicies returns a slice of output flags that are used in the policies' actions
func getOutputFlagsFromPolicies(policies []policy.PolicyFile) []string {
	m := make(map[string]bool)
	for _, p := range policies {
		key := strings.TrimSpace(p.DefaultAction)

		// log action translates to json:stdout
		if key == "log" {
			key = "json"
		}

		m[key] = true

		for _, r := range p.Rules {
			if r.Action != "" {
				key = strings.TrimSpace(r.Action)

				// log action translates to json:stdout
				if key == "log" {
					key = "json"
				}

				m[key] = true
			}
		}
	}

	outputSlice := make([]string, 0)
	for k := range m {
		outputSlice = append(outputSlice, k)
	}

	return outputSlice
}
