package cobra

import (
	"strings"

	"github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/policy"
)

func getConfigAndPrinterFromPoliciesFlags(cfg config.Config, policyFlags, outputFlags []string) (config.Config, printer.EventPrinter, error) {
	policyFiles, err := policy.PoliciesFromPaths(policyFlags)
	if err != nil {
		return cfg, nil, err
	}

	policyScopeMap, policyEventsMap, err := flags.PrepareFilterMapsFromPolicies(policyFiles)
	if err != nil {
		return cfg, nil, err
	}

	policies, err := flags.CreatePolicies(policyScopeMap, policyEventsMap, true)
	if err != nil {
		return cfg, nil, err
	}
	cfg.Policies = policies

	outputFlags, err = getOutputFlagsFromPolicies(outputFlags, policyFiles)
	if err != nil {
		return cfg, nil, err
	}

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

func getConfigAndPrinterFromFilterFlags(cfg config.Config, scopeFlags, eventFlags, outputFlags []string) (config.Config, printer.EventPrinter, error) {
	policyScopeMap, err := flags.PrepareScopeMapFromFlags(scopeFlags)
	if err != nil {
		return cfg, nil, err
	}

	policyEventsMap, err := flags.PrepareEventMapFromFlags(eventFlags)
	if err != nil {
		return cfg, nil, err
	}

	policies, err := flags.CreatePolicies(policyScopeMap, policyEventsMap, true)
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

// getOutputFlagsFromPolicies returns a slice of output flags that are used in the policies' actions
func getOutputFlagsFromPolicies(outputFlags []string, policies []policy.PolicyFile) ([]string, error) {
	// a map of the actions used in the policies
	actionsMap := make(map[string]bool)

	for _, p := range policies {
		for _, action := range p.DefaultActions {
			if action != "" {
				actionsMap[strings.TrimSpace(action)] = false
			}
		}

		for _, r := range p.Rules {
			for _, action := range r.Actions {
				if action != "" {
					actionsMap[strings.TrimSpace(action)] = false
				}
			}
		}
	}

	outputSlice := make([]string, 0)

	// parse output flags to check which printers were configured
	for _, o := range outputFlags {
		outputParts := strings.SplitN(o, ":", 2)

		switch outputParts[0] {
		case "forward", "webhook":
			actionsMap[outputParts[0]] = true
		case "table", "table-verbose", "json", "gob":
			actionsMap["log"] = true
		}

		outputSlice = append(outputSlice, o)
	}

	// if printer was not defined for action log, return default to table:stdout
	// if printers were not defined for actions webhook and forward, return error.
	for k, v := range actionsMap {
		if !v {
			if k == "log" {
				outputSlice = append(outputSlice, "table:stdout")
				continue
			}
			return nil, errfmt.Errorf("policy action %q has no printer configured, please configure the printer with --output", k)
		}
	}

	return outputSlice, nil
}
