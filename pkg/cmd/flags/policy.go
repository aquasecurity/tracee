package flags

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/policy"
)

// PolicyFile is the structure of the policy file
type PolicyFile struct {
	Name          string   `yaml:"name"`
	Description   string   `yaml:"description"`
	Scope         []string `yaml:"scope"`
	DefaultAction string   `yaml:"defaultAction"`
	Rules         []Rule   `yaml:"rules"`
}

// Rule is the structure of the rule in the policy file
type Rule struct {
	Event  string   `yaml:"event"`
	Filter []string `yaml:"filter"`
	Action string   `yaml:"action"`
}

// PrepareFilterMapForPolicies prepares the FilterMap for the policies
func PrepareFilterMapFromPolicies(policies []PolicyFile) (FilterMap, error) {
	filterMap := make(FilterMap)

	if len(policies) == 0 {
		return nil, errfmt.Errorf("no policies provided")
	}

	if len(policies) > policy.MaxPolicies {
		return nil, errfmt.Errorf("too many policies provided, there is a limit of %d policies", policy.MaxPolicies)
	}

	policyNames := make(map[string]bool)

	for pIdx, p := range policies {
		err := validatePolicy(p)
		if err != nil {
			return nil, err
		}

		if _, ok := policyNames[p.Name]; ok {
			return nil, errfmt.Errorf("policy %s already exist", p.Name)
		}
		policyNames[p.Name] = true

		filterFlags := make([]*filterFlag, 0)

		err = validateAction(p.Name, p.DefaultAction)
		if err != nil {
			return nil, err
		}

		// scope
		for _, s := range p.Scope {
			s = strings.ReplaceAll(s, " ", "")

			if s == "global" && len(p.Scope) > 1 {
				return nil, errfmt.Errorf("policy %s, global scope must be unique", p.Name)
			}

			if s == "global" {
				break
			}

			var scope, filterName, operatorAndValues string

			switch s {
			case "follow", "!container", "container":
				scope = s
				filterName = s
				operatorAndValues = ""
			default:
				operatorIdx := strings.IndexAny(s, "=!<>")

				if operatorIdx == -1 {
					return nil, errfmt.Errorf("policy %s, scope %s is not valid", p.Name, s)
				}

				scope = s[:operatorIdx]
				filterName = s[:operatorIdx]
				operatorAndValues = s[operatorIdx:]
			}

			err := validateScope(p.Name, scope)
			if err != nil {
				return nil, err
			}

			filterFlags = append(filterFlags, &filterFlag{
				full:              s,
				filterName:        filterName,
				operatorAndValues: operatorAndValues,
				policyIdx:         pIdx,
				policyName:        p.Name,
			})
		}

		events := make(map[string]bool)

		for _, r := range p.Rules {
			err := validateEvent(p.Name, r.Event)
			if err != nil {
				return nil, err
			}

			// Currently, an event can only be used once in the policy. Support for using the same
			// event, multiple times, with different filters, shall be implemented in the future.
			if _, ok := events[r.Event]; ok {
				return nil, errfmt.Errorf("policy %s, event %s is duplicated", p.Name, r.Event)
			}

			events[r.Event] = true

			filterFlags = append(filterFlags, &filterFlag{
				full:              fmt.Sprintf("event=%s", r.Event),
				filterName:        "event",
				operatorAndValues: fmt.Sprintf("=%s", r.Event),
				policyIdx:         pIdx,
				policyName:        p.Name,
			})

			for _, f := range r.Filter {
				f = strings.ReplaceAll(f, " ", "")

				operatorIdx := strings.IndexAny(f, "=!<>")

				if operatorIdx == -1 {
					return nil, errfmt.Errorf("invalid filter operator: %s", f)
				}

				filterName := f[:operatorIdx]
				operatorAndValues := f[operatorIdx:]

				// args
				if strings.HasPrefix(f, "args.") {
					filterFlags = append(filterFlags, &filterFlag{
						full:              fmt.Sprintf("%s.%s", r.Event, f),
						filterName:        fmt.Sprintf("%s.%s", r.Event, filterName),
						operatorAndValues: operatorAndValues,
						policyIdx:         pIdx,
						policyName:        p.Name,
					})

					continue
				}

				// retval
				if strings.HasPrefix(f, "retval") {
					filterFlags = append(filterFlags, &filterFlag{
						full:              fmt.Sprintf("%s.%s", r.Event, f),
						filterName:        fmt.Sprintf("%s.%s", r.Event, filterName),
						operatorAndValues: operatorAndValues,
						policyIdx:         pIdx,
						policyName:        p.Name,
					})
					continue
				}

				err = validateContext(p.Name, filterName)
				if err != nil {
					return nil, err
				}

				// context
				filterFlags = append(filterFlags, &filterFlag{
					full:              fmt.Sprintf("%s.context.%s", r.Event, f),
					filterName:        fmt.Sprintf("%s.context.%s", r.Event, filterName),
					operatorAndValues: operatorAndValues,
					policyIdx:         pIdx,
					policyName:        p.Name,
				})
			}
		}

		filterMap[pIdx] = filterFlags
	}

	return filterMap, nil
}

func validatePolicy(p PolicyFile) error {
	if p.Name == "" {
		return errfmt.Errorf("policy name cannot be empty")
	}

	if p.Description == "" {
		return errfmt.Errorf("policy %s, description cannot be empty", p.Name)
	}

	if p.Scope == nil || len(p.Scope) == 0 {
		return errfmt.Errorf("policy %s, scope cannot be empty", p.Name)
	}

	if p.Rules == nil || len(p.Rules) == 0 {
		return errfmt.Errorf("policy %s, rules cannot be empty", p.Name)
	}

	if p.DefaultAction == "" {
		return errfmt.Errorf("policy %s, default action cannot be empty", p.Name)
	}

	return nil
}

func validateAction(policyName, a string) error {
	actions := []string{
		"log",
	}

	for _, action := range actions {
		if a == action {
			return nil
		}
	}

	return errfmt.Errorf("policy %s, action %s is not valid", policyName, a)
}

func validateScope(policyName, s string) error {
	scopes := []string{
		"uid",
		"pid",
		"mntns",
		"pidns",
		"uts",
		"comm",
		"container",
		"!container",
		"tree",
		"binary",
		"bin",
		"follow",
	}

	for _, scope := range scopes {
		if s == scope {
			return nil
		}
	}

	return errfmt.Errorf("policy %s, scope %s is not valid", policyName, s)
}

func validateEvent(policyName, eventName string) error {
	if eventName == "" {
		return errfmt.Errorf("policy %s, event cannot be empty", policyName)
	}

	_, ok := events.Definitions.GetID(eventName)
	if !ok {
		return errfmt.Errorf("policy %s, event %s is not valid", policyName, eventName)
	}
	return nil
}

func validateContext(policyName, c string) error {
	contexts := []string{
		"timestamp",
		"processorId",
		"p",
		"pid",
		"processId",
		"tid",
		"threadId",
		"ppid",
		"parentProcessId",
		"hostTid",
		"hostThreadId",
		"hostPid",
		"hostParentProcessId",
		"uid",
		"userId",
		"mntns",
		"mountNamespace",
		"pidns",
		"pidNamespace",
		"processName",
		"comm",
		"hostName",
		"cgroupId",
		"host",
		"container",
		"containerId",
		"containerImage",
		"containerName",
		"podName",
		"podNamespace",
		"podUid",
		"syscall",
	}

	for _, context := range contexts {
		if c == context {
			return nil
		}
	}

	return errfmt.Errorf("policy %s, filter %s is not valid", policyName, c)
}
