package flags

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	k8s "github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
	"github.com/aquasecurity/tracee/pkg/policy"
)

// PrepareFilterMapsForPolicies prepares the scope and events PolicyFilterMap for the policies
func PrepareFilterMapsFromPolicies(policies []k8s.PolicyInterface) (PolicyScopeMap, PolicyEventMap, error) {
	policyScopeMap := make(PolicyScopeMap)
	policyEventsMap := make(PolicyEventMap)

	if len(policies) == 0 {
		return nil, nil, errfmt.Errorf("no policies provided")
	}

	if len(policies) > policy.PolicyMax {
		return nil, nil, errfmt.Errorf("too many policies provided, there is a limit of %d policies", policy.PolicyMax)
	}

	policyNames := make(map[string]bool)

	for pIdx, p := range policies {
		if _, ok := policyNames[p.GetName()]; ok {
			return nil, nil, errfmt.Errorf("policy %s already exist", p.GetName())
		}
		policyNames[p.GetName()] = true

		scopeFlags := make([]scopeFlag, 0)

		// scope
		for _, s := range p.GetScope() {
			s = strings.ReplaceAll(s, " ", "")

			if s == "global" && len(p.GetScope()) > 1 {
				return nil, nil, errfmt.Errorf("policy %s, global scope must be unique", p.GetName())
			}

			if s == "global" {
				break
			}

			parsed, err := parseScopeFlag(s)
			if err != nil {
				return nil, nil, errfmt.WrapError(err)
			}

			scopeFlags = append(scopeFlags, parsed)
		}

		policyScopeMap[pIdx] = policyScopes{
			policyName: p.GetName(),
			scopeFlags: scopeFlags,
		}

		eventFlags := make([]eventFlag, 0)

		for _, r := range p.GetRules() {
			evtFlags, err := parseEventFlag(r.Event)
			if err != nil {
				return nil, nil, errfmt.WrapError(err)
			}
			eventFlags = append(eventFlags, evtFlags...)

			for _, f := range r.Filters {
				// event data or return value filter
				// option "args." will be deprecate in future
				if strings.HasPrefix(f, "data.") || strings.HasPrefix(f, "args.") ||
					strings.HasPrefix(f, "retval") {
					evtFilterFlags, err := parseEventFlag(fmt.Sprintf("%s.%s", r.Event, f))
					if err != nil {
						return nil, nil, errfmt.WrapError(err)
					}
					eventFlags = append(eventFlags, evtFilterFlags...)

					continue
				}

				// at this point we know the filter is an event scope filter
				// scope filters are provided without "scope." prefix so we need to add it
				evtScopeFlags, err := parseEventFlag(fmt.Sprintf("%s.scope.%s", r.Event, f))
				if err != nil {
					return nil, nil, errfmt.WrapError(err)
				}
				eventFlags = append(eventFlags, evtScopeFlags...)
			}
		}

		policyEventsMap[pIdx] = policyEvents{
			policyName: p.GetName(),
			eventFlags: eventFlags,
		}
	}

	return policyScopeMap, policyEventsMap, nil
}

// CreatePolicies creates a Policies object from the scope and events maps.
func CreatePolicies(policyScopeMap PolicyScopeMap, policyEventsMap PolicyEventMap, newBinary bool) ([]*policy.Policy, error) {
	policies := make([]*policy.Policy, 0, len(policyScopeMap))

	for policyIdx, policyScope := range policyScopeMap {
		policyEvents, ok := policyEventsMap[policyIdx]
		if !ok {
			return nil, InvalidFlagEmpty()
		}

		pol, err := createSinglePolicy(policyIdx, policyScope, policyEvents, newBinary)
		if err != nil {
			return nil, err
		}
		policies = append(policies, pol)
	}

	return policies, nil
}

func createSinglePolicy(policyIdx int, policyScope policyScopes, policyEvents policyEvents, newBinary bool) (*policy.Policy, error) {
	p := policy.NewPolicy()
	p.ID = policyIdx
	p.Name = policyScope.policyName

	if err := parseScopeFilters(p, policyScope.scopeFlags, newBinary); err != nil {
		return nil, err
	}

	if err := parseEventFilters(p, policyEvents.eventFlags); err != nil {
		return nil, err
	}

	return p, nil
}

func parseScopeFilters(p *policy.Policy, scopeFlags []scopeFlag, newBinary bool) error {
	for _, scopeFlag := range scopeFlags {
		switch scopeFlag.scopeName {
		case "comm":
			if err := p.CommFilter.Parse(scopeFlag.operatorAndValues); err != nil {
				return err
			}

		case "exec", "executable", "bin", "binary":
			if err := p.BinaryFilter.Parse(scopeFlag.operatorAndValues); err != nil {
				return err
			}

		case "container":
			switch {
			case scopeFlag.operator == "not":
				if err := p.ContFilter.Parse(scopeFlag.full); err != nil {
					return err
				}
			case scopeFlag.operatorAndValues == "=new":
				if err := p.NewContFilter.Parse("new"); err != nil {
					return err
				}
			case scopeFlag.operatorAndValues == "!=new":
				if err := p.ContFilter.Parse(scopeFlag.scopeName); err != nil {
					return err
				}
				if err := p.NewContFilter.Parse("!new"); err != nil {
					return err
				}
			case scopeFlag.operator == "=":
				if err := p.ContIDFilter.Parse(scopeFlag.operatorAndValues); err != nil {
					return err
				}
			default:
				if err := p.ContFilter.Parse(scopeFlag.scopeName); err != nil {
					return err
				}
			}

		case "mntns":
			if strings.ContainsAny(scopeFlag.operator, "<>") {
				return filters.InvalidExpression(scopeFlag.operatorAndValues)
			}
			if err := p.MntNSFilter.Parse(scopeFlag.operatorAndValues); err != nil {
				return err
			}

		case "pidns":
			if strings.ContainsAny(scopeFlag.operator, "<>") {
				return filters.InvalidExpression(scopeFlag.operatorAndValues)
			}
			if err := p.PidNSFilter.Parse(scopeFlag.operatorAndValues); err != nil {
				return err
			}

		case "tree":
			if err := p.ProcessTreeFilter.Parse(scopeFlag.operatorAndValues); err != nil {
				return err
			}

		case "pid":
			switch scopeFlag.operatorAndValues {
			case "=new":
				if err := p.NewPidFilter.Parse("new"); err != nil {
					return err
				}
			case "!=new":
				if err := p.NewPidFilter.Parse("!new"); err != nil {
					return err
				}
			default:
				if err := p.PIDFilter.Parse(scopeFlag.operatorAndValues); err != nil {
					return err
				}
			}

		case "uts":
			if err := p.UTSFilter.Parse(scopeFlag.operatorAndValues); err != nil {
				return err
			}

		case "uid":
			if err := p.UIDFilter.Parse(scopeFlag.operatorAndValues); err != nil {
				return err
			}

		case "follow":
			p.Follow = true

		default:
			return InvalidScopeOptionError(scopeFlag.full, newBinary)
		}
	}
	return nil
}

func parseEventFilters(p *policy.Policy, eventFlags []eventFlag) error {
	eventNamesToID := events.Core.NamesToIDs()
	// remove internal events since they shouldn't be accessible by users
	for event, id := range eventNamesToID {
		if events.Core.GetDefinitionByID(id).IsInternal() {
			delete(eventNamesToID, event)
		}
	}

	// map sets to events
	setsToEvents := make(map[string][]events.ID)
	for _, eventDefinition := range events.Core.GetDefinitions() {
		for _, set := range eventDefinition.GetSets() {
			setsToEvents[set] = append(setsToEvents[set], eventDefinition.GetID())
		}
	}

	excludedEvents := make([]string, 0)

	// Process event flags
	for _, evtFlag := range eventFlags {
		if evtFlag.eventOptionType == "" && evtFlag.operator == "-" {
			excludedEvents = append(excludedEvents, evtFlag.eventName)
			continue
		}

		eventIdToName := make(map[events.ID]string)
		if strings.HasSuffix(evtFlag.eventName, "*") {
			found := false
			prefix := evtFlag.eventName[:len(evtFlag.eventName)-1]
			for event, id := range eventNamesToID {
				if strings.HasPrefix(event, prefix) {
					eventIdToName[id] = event
					found = true
				}
			}
			if !found {
				return InvalidEventError(evtFlag.eventName)
			}
		} else {
			id, ok := eventNamesToID[evtFlag.eventName]
			if !ok {
				// no matching event - maybe it is actually a set?
				setEvents, ok := setsToEvents[evtFlag.eventName]
				if !ok {
					return InvalidEventError(evtFlag.eventName)
				}
				for _, id := range setEvents {
					eventIdToName[id] = events.Core.GetDefinitionByID(id).GetName()
				}
			} else {
				eventIdToName[id] = evtFlag.eventName
			}
		}

		for eventId := range eventIdToName {
			if _, ok := p.Rules[eventId]; !ok {
				p.Rules[eventId] = policy.RuleData{
					EventID:     eventId,
					ScopeFilter: filters.NewScopeFilter(),
					DataFilter:  filters.NewDataFilter(),
					RetFilter:   filters.NewIntFilter(),
				}
			}

			if evtFlag.eventOptionType == "" {
				continue
			}

			switch evtFlag.eventOptionType {
			case "retval":
				if err := p.Rules[eventId].RetFilter.Parse(evtFlag.operatorAndValues); err != nil {
					return err
				}
			case "scope":
				if err := p.Rules[eventId].ScopeFilter.Parse(evtFlag.eventOptionName, evtFlag.operatorAndValues); err != nil {
					return err
				}
			case "data", "args":
				if err := p.Rules[eventId].DataFilter.Parse(eventId, evtFlag.eventOptionName, evtFlag.operatorAndValues); err != nil {
					return err
				}
			default:
				return InvalidFilterFlagFormat(evtFlag.full)
			}
		}
	}

	// if no events were specified, add all events from the default set
	if len(p.Rules) == 0 {
		for _, eventId := range setsToEvents["default"] {
			if _, ok := p.Rules[eventId]; !ok {
				p.Rules[eventId] = policy.RuleData{
					EventID:     eventId,
					ScopeFilter: filters.NewScopeFilter(),
					DataFilter:  filters.NewDataFilter(),
					RetFilter:   filters.NewIntFilter(),
				}
			}
		}
	}

	// remove excluded events from the policy
	for _, eventName := range excludedEvents {
		if _, ok := eventNamesToID[eventName]; !ok {
			return InvalidEventExcludeError(eventName)
		}
		delete(p.Rules, eventNamesToID[eventName])
	}

	return nil
}
