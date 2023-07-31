package flags

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/policy/v1beta1"
)

// PrepareFilterMapsForPolicies prepares the scope and events PolicyFilterMap for the policies
func PrepareFilterMapsFromPolicies(policies []v1beta1.PolicyFile) (PolicyScopeMap, PolicyEventMap, error) {
	policyScopeMap := make(PolicyScopeMap)
	policyEventsMap := make(PolicyEventMap)

	if len(policies) == 0 {
		return nil, nil, errfmt.Errorf("no policies provided")
	}

	if len(policies) > policy.MaxPolicies {
		return nil, nil, errfmt.Errorf("too many policies provided, there is a limit of %d policies", policy.MaxPolicies)
	}

	policyNames := make(map[string]bool)

	for pIdx, p := range policies {
		if _, ok := policyNames[p.Name()]; ok {
			return nil, nil, errfmt.Errorf("policy %s already exist", p.Name())
		}
		policyNames[p.Name()] = true

		scopeFlags := make([]scopeFlag, 0)

		// scope
		for _, s := range p.Scope() {
			s = strings.ReplaceAll(s, " ", "")

			if s == "global" && len(p.Scope()) > 1 {
				return nil, nil, errfmt.Errorf("policy %s, global scope must be unique", p.Name())
			}

			if s == "global" {
				break
			}

			var scopeName, operatorAndValues string

			switch s {
			case "follow", "!container", "container":
				scopeName = s
				operatorAndValues = ""
			default:
				operatorIdx := strings.IndexAny(s, "=!<>")
				scopeName = s[:operatorIdx]
				operatorAndValues = s[operatorIdx:]
			}

			scopeFlags = append(scopeFlags, scopeFlag{
				full:              s,
				scopeName:         scopeName,
				operatorAndValues: operatorAndValues,
			})
		}

		policyScopeMap[pIdx] = policyScopes{
			policyName: p.Name(),
			scopeFlags: scopeFlags,
		}

		eventFlags := make([]eventFlag, 0)

		for _, r := range p.Rules() {
			evtFlag, err := parseEventFlag(r.Event)
			if err != nil {
				return nil, nil, errfmt.WrapError(err)
			}
			eventFlags = append(eventFlags, evtFlag)

			for _, f := range r.Filters {
				// event argument or return value filter
				if strings.HasPrefix(f, "args.") || strings.HasPrefix(f, "retval") {
					evtFilterFlag, err := parseEventFlag(fmt.Sprintf("%s.%s", r.Event, f))
					if err != nil {
						return nil, nil, errfmt.WrapError(err)
					}
					eventFlags = append(eventFlags, evtFilterFlag)

					continue
				}

				// at this point we know the filter is an event context filter
				// context filters are provided without "context." prefix so we need to add it
				evtContextFlag, err := parseEventFlag(fmt.Sprintf("%s.context.%s", r.Event, f))
				if err != nil {
					return nil, nil, errfmt.WrapError(err)
				}
				eventFlags = append(eventFlags, evtContextFlag)
			}
		}

		policyEventsMap[pIdx] = policyEvents{
			policyName: p.Name(),
			eventFlags: eventFlags,
		}
	}

	return policyScopeMap, policyEventsMap, nil
}

// CreatePolicies creates a Policies object from the scope and events maps.
func CreatePolicies(policyScopeMap PolicyScopeMap, policyEventsMap PolicyEventMap, newBinary bool) (*policy.Policies, error) {
	eventsNameToID := events.Core.NamesToIDs()
	// remove internal events since they shouldn't be accessible by users
	for event, id := range eventsNameToID {
		evtDef := events.Core.GetEventByID(id)
		if evtDef.IsInternal() {
			delete(eventsNameToID, event)
		}
	}

	policies := policy.NewPolicies()
	for policyIdx, policyScopeFilters := range policyScopeMap {
		p := policy.NewPolicy()
		p.ID = policyIdx
		p.Name = policyScopeFilters.policyName

		for _, scopeFlag := range policyScopeFilters.scopeFlags {
			// The filters which are more common (container, event, pid, set, uid) can be given using a prefix of them.
			// Other filters should be given using their full name.
			// To avoid collisions between filters that share the same prefix, put the filters which should have an exact match first!
			if scopeFlag.scopeName == "comm" {
				err := p.CommFilter.Parse(scopeFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if scopeFlag.scopeName == "binary" || scopeFlag.scopeName == "bin" {
				err := p.BinaryFilter.Parse(scopeFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.HasPrefix("container", scopeFlag.scopeName) {
				if scopeFlag.operatorAndValues == "=new" {
					err := p.NewContFilter.Parse("new")
					if err != nil {
						return nil, err
					}
					continue
				}
				if scopeFlag.operatorAndValues == "!=new" {
					err := p.ContFilter.Parse(scopeFlag.scopeName)
					if err != nil {
						return nil, err
					}
					err = p.NewContFilter.Parse("!new")
					if err != nil {
						return nil, err
					}
					continue
				}
				if scopeFlag.operator == "=" {
					err := p.ContIDFilter.Parse(scopeFlag.operatorAndValues)
					if err != nil {
						return nil, err
					}
					continue
				}
				err := p.ContFilter.Parse(scopeFlag.scopeName)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.HasPrefix("!container", scopeFlag.scopeName) {
				err := p.ContFilter.Parse(scopeFlag.scopeName)
				if err != nil {
					return nil, err
				}
				continue
			}

			if scopeFlag.scopeName == "mntns" {
				if strings.ContainsAny(scopeFlag.operator, "<>") {
					return nil, filters.InvalidExpression(scopeFlag.operatorAndValues)
				}
				err := p.MntNSFilter.Parse(scopeFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if scopeFlag.scopeName == "pidns" {
				if strings.ContainsAny(scopeFlag.operator, "<>") {
					return nil, filters.InvalidExpression(scopeFlag.operatorAndValues)
				}
				err := p.PidNSFilter.Parse(scopeFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if scopeFlag.scopeName == "tree" {
				err := p.ProcessTreeFilter.Parse(scopeFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.HasPrefix("pid", scopeFlag.scopeName) {
				if scopeFlag.operatorAndValues == "=new" {
					if err := p.NewPidFilter.Parse("new"); err != nil {
						return nil, err
					}
					continue
				}
				if scopeFlag.operatorAndValues == "!=new" {
					if err := p.NewPidFilter.Parse("!new"); err != nil {
						return nil, err
					}
					continue
				}
				err := p.PIDFilter.Parse(scopeFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if scopeFlag.scopeName == "uts" {
				err := p.UTSFilter.Parse(scopeFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.HasPrefix("uid", scopeFlag.scopeName) {
				err := p.UIDFilter.Parse(scopeFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.HasPrefix("follow", scopeFlag.scopeName) {
				p.Follow = true
				continue
			}

			return nil, InvalidScopeOptionError(scopeFlag.full, newBinary)
		}

		eventFilter := eventFilter{
			Equal:    []string{},
			NotEqual: []string{},
		}

		policyEvents, ok := policyEventsMap[policyIdx]
		if !ok {
			return nil, InvalidFlagEmpty()
		}

		for _, evtFlag := range policyEvents.eventFlags {
			if evtFlag.operator == "" && evtFlag.eventOptionType == "" {
				// no operator and no event option type means that the flag contains only event names
				evtsNames := strings.Split(evtFlag.full, ",")
				for _, evtName := range evtsNames {
					if !strings.HasPrefix(evtName, "-") {
						eventFilter.Equal = append(eventFilter.Equal, evtName)
					} else {
						eventFilter.NotEqual = append(eventFilter.NotEqual, evtName[1:])
					}
				}
				continue
			}

			// at this point, we can assume that event flag is an event option filter (args, retval, context),
			// so, as a sugar, we can add the event name to be filtered
			eventFilter.Equal = append(eventFilter.Equal, evtFlag.eventName)

			evtFilter := evtFlag.eventFilter
			operatorAndValues := evtFlag.operatorAndValues

			if evtFlag.eventOptionType == "retval" {
				err := p.RetFilter.Parse(evtFilter, operatorAndValues, eventsNameToID)
				if err != nil {
					return nil, err
				}
				continue
			}

			if evtFlag.eventOptionType == "context" {
				err := p.ContextFilter.Parse(evtFilter, operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if evtFlag.eventOptionType == "args" {
				err := p.ArgFilter.Parse(evtFilter, operatorAndValues, eventsNameToID)
				if err != nil {
					return nil, err
				}
				continue
			}

			return nil, InvalidFilterFlagFormat(evtFlag.full)
		}

		var err error
		p.EventsToTrace, err = prepareEventsToTrace(eventFilter, eventsNameToID)
		if err != nil {
			return nil, err
		}

		err = policies.Set(p)
		if err != nil {
			logger.Warnw("Setting policy", "error", err)
		}
	}

	if len(policies.Map()) == 0 {
		// if nothing was set, let us consider it as a single default policy
		eventFilter := eventFilter{
			Equal:    []string{},
			NotEqual: []string{},
		}

		var err error
		newPolicy := policy.NewPolicy()
		newPolicy.EventsToTrace, err = prepareEventsToTrace(eventFilter, eventsNameToID)
		if err != nil {
			return nil, err
		}

		err = policies.Add(newPolicy)
		if err != nil {
			return nil, err
		}
	}

	return policies, nil
}
