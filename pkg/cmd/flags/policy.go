package flags

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/policy"
)

// PrepareFilterMapsForPolicies prepares the scope and events PolicyFilterMap for the policies
func PrepareFilterMapsFromPolicies(policies []policy.PolicyFile) (PolicyFilterMap, PolicyEventMap, error) {
	policyScopeMap := make(PolicyFilterMap)
	policyEventsMap := make(PolicyEventMap)

	if len(policies) == 0 {
		return nil, nil, errfmt.Errorf("no policies provided")
	}

	if len(policies) > policy.MaxPolicies {
		return nil, nil, errfmt.Errorf("too many policies provided, there is a limit of %d policies", policy.MaxPolicies)
	}

	policyNames := make(map[string]bool)

	for pIdx, p := range policies {
		if _, ok := policyNames[p.Name]; ok {
			return nil, nil, errfmt.Errorf("policy %s already exist", p.Name)
		}
		policyNames[p.Name] = true

		filterFlags := make([]*filterFlag, 0)

		// scope
		for _, s := range p.Scope {
			s = strings.ReplaceAll(s, " ", "")

			if s == "global" && len(p.Scope) > 1 {
				return nil, nil, errfmt.Errorf("policy %s, global scope must be unique", p.Name)
			}

			if s == "global" {
				break
			}

			var filterName, operatorAndValues string

			switch s {
			case "follow", "!container", "container":
				filterName = s
				operatorAndValues = ""
			default:
				operatorIdx := strings.IndexAny(s, "=!<>")
				filterName = s[:operatorIdx]
				operatorAndValues = s[operatorIdx:]
			}

			filterFlags = append(filterFlags, &filterFlag{
				full:              s,
				filterName:        filterName,
				operatorAndValues: operatorAndValues,
			})
		}

		policyScopeMap[pIdx] = policyFilters{
			policyName:  p.Name,
			filterFlags: filterFlags,
		}

		eventFlags := make([]*eventFlag, 0)

		for _, r := range p.Rules {
			eventFlags = append(eventFlags, &eventFlag{
				full:              r.Event,
				eventName:         r.Event,
				filter:            "",
			})

			for _, f := range r.Filter {
				// event argument or return value filter
				if strings.HasPrefix(f, "args.") || strings.HasPrefix(f, "retval") {
					eventFlags = append(eventFlags, &eventFlag{
						full:              fmt.Sprintf("%s.%s", r.Event, f),
						eventName:         r.Event,
						filter:            f,
					})
					continue
				}

				// at this point we know the filter is an event context filter

				// operatorIdx := strings.IndexAny(f, "=!")

				// if operatorIdx == -1 {
				// 	return nil, nil, errfmt.Errorf("invalid filter operator: %s", f)
				// }

				// filterName := f[:operatorIdx]

				// context filters are provided without "context." prefix so we need to add it
				eventFlags = append(eventFlags, &eventFlag{
					full:              fmt.Sprintf("%s.context.%s", r.Event, f),
					eventName:         r.Event,
					filter:            f,
				})
			}
		}

		policyEventsMap[pIdx] = policyEvents{
			policyName:  p.Name,
			eventFlags:  eventFlags,
		}
	}

	return policyScopeMap, policyEventsMap, nil
}
