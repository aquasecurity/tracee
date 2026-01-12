package flags

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	k8s "github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
	"github.com/aquasecurity/tracee/pkg/policy"
)

// PrepareFilterMapsForPolicies prepares the scope and events PolicyFilterMap for the policies
func PrepareFilterMapsFromPolicies(policies []k8s.PolicyInterface, detectors []detection.EventDetector) (PolicyScopeMap, PolicyEventMap, error) {
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
			detectors:  detectors,
		}
	}

	return policyScopeMap, policyEventsMap, nil
}

// CreatePolicies creates a Policies object from the scope and events maps.
func CreatePolicies(policyScopeMap PolicyScopeMap, policyEventsMap PolicyEventMap) ([]*policy.Policy, error) {
	policies := make([]*policy.Policy, 0, len(policyScopeMap))

	for policyIdx, policyScope := range policyScopeMap {
		policyEvents, ok := policyEventsMap[policyIdx]
		if !ok {
			return nil, InvalidFlagEmpty()
		}

		pol, err := createSinglePolicy(policyIdx, policyScope, policyEvents)
		if err != nil {
			return nil, err
		}
		policies = append(policies, pol)
	}

	return policies, nil
}

func createSinglePolicy(policyIdx int, policyScope policyScopes, policyEvents policyEvents) (*policy.Policy, error) {
	p := policy.NewPolicy()
	p.ID = policyIdx
	p.Name = policyScope.policyName

	if err := parseScopeFilters(p, policyScope.scopeFlags); err != nil {
		return nil, err
	}

	if err := parseEventFilters(p, policyEvents.eventFlags, policyEvents.detectors); err != nil {
		return nil, err
	}

	return p, nil
}

func parseScopeFilters(p *policy.Policy, scopeFlags []scopeFlag) error {
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
				if err := p.NewContFilter.Parse("not-new"); err != nil {
					return err
				}
			case scopeFlag.operatorAndValues == "=started":
				// Container started state filter: container=started (only started containers)
				if err := p.ContFilter.Parse(scopeFlag.scopeName); err != nil {
					return err
				}
				if err := p.ContStartedFilter.Parse("started"); err != nil {
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
				if err := p.NewPidFilter.Parse("not-new"); err != nil {
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
			return InvalidScopeOptionError(scopeFlag.full)
		}
	}
	return nil
}

// parseEventFilters populates the policy's event rules based on parsed event flags.
// If detectors is non-nil, threat.* patterns will be expanded into matching detector event IDs.
func parseEventFilters(p *policy.Policy, eventFlags []eventFlag, detectors []detection.EventDetector) error {
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

		// Check if this is a threat.* pattern - expand into detector event IDs
		// Note: parseEventFlag splits "threat.severity=critical" into eventName="threat", eventOptionType="severity"
		if evtFlag.eventName == "threat" && evtFlag.eventOptionType != "" && detectors != nil {
			matchingEventIDs, err := expandThreatPattern(evtFlag, detectors, eventNamesToID)
			if err != nil {
				return err
			}

			// Add all matching detector events to the policy
			for eventId := range matchingEventIDs {
				if _, ok := p.Rules[eventId]; !ok {
					p.Rules[eventId] = policy.RuleData{
						EventID:     eventId,
						ScopeFilter: filters.NewScopeFilter(),
						DataFilter:  filters.NewDataFilter(),
						RetFilter:   filters.NewIntFilter(),
					}
				}
			}

			// Skip regular event processing for threat patterns
			continue
		}

		// Check if this is a tag= pattern - expand into events with matching tags (sets)
		if evtFlag.eventName == "tag" && evtFlag.operator == "=" {
			// Parse comma-separated tag values (OR logic within values)
			tags := strings.Split(evtFlag.values, ",")
			found := false
			for _, tag := range tags {
				tag = strings.TrimSpace(tag)
				if tag == "" {
					continue
				}
				if setEvents, ok := setsToEvents[tag]; ok {
					for _, id := range setEvents {
						if _, ok := p.Rules[id]; !ok {
							p.Rules[id] = policy.RuleData{
								EventID:     id,
								ScopeFilter: filters.NewScopeFilter(),
								DataFilter:  filters.NewDataFilter(),
								RetFilter:   filters.NewIntFilter(),
							}
						}
					}
					found = true
				}
			}
			if !found {
				return InvalidTagError(evtFlag.values)
			}
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
				// Event name not found - no longer falls back to sets
				// Use explicit tag=<set_name> syntax instead
				return InvalidEventError(evtFlag.eventName)
			}
			eventIdToName[id] = evtFlag.eventName
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

// expandThreatPattern expands a threat.* pattern into matching detector event IDs.
// Supports patterns like:
//   - threat.severity=critical
//   - threat.severity>=high
//   - threat.mitre.technique=T1055
//   - threat.mitre.tactic="Defense Evasion"
//   - threat.name=process_injection
func expandThreatPattern(evtFlag eventFlag, detectors []detection.EventDetector, eventNamesToID map[string]events.ID) (map[events.ID]string, error) {
	if detectors == nil {
		return nil, errfmt.Errorf("no detectors provided for threat pattern: %s", evtFlag.full)
	}

	// Parse the threat property path from eventOptionType and eventOptionName
	// eventFlag parsing splits "threat.severity=critical" into:
	//   eventName="threat", eventOptionType="severity", values="critical"
	// or "threat.mitre.technique=T1055" into:
	//   eventName="threat", eventOptionType="mitre", eventOptionName="technique", values="T1055"

	if evtFlag.eventName != "threat" {
		return nil, errfmt.Errorf("invalid threat pattern: %s", evtFlag.full)
	}

	if evtFlag.eventOptionType == "" {
		return nil, errfmt.Errorf("invalid threat pattern: %s", evtFlag.full)
	}

	// Build the property path from eventOptionType and eventOptionName
	propertyPath := evtFlag.eventOptionType
	if evtFlag.eventOptionName != "" {
		propertyPath = evtFlag.eventOptionType + "." + evtFlag.eventOptionName
	}

	// Threat patterns must have an operator and value
	if evtFlag.operator == "" || evtFlag.values == "" {
		return nil, errfmt.Errorf("threat pattern requires operator and value: %s", evtFlag.full)
	}

	matchingEvents := make(map[events.ID]string)

	// Iterate through all detectors and check their threat metadata
	for _, detector := range detectors {
		def := detector.GetDefinition()

		// Skip detectors without threat metadata
		if def.ThreatMetadata == nil {
			continue
		}

		// Check if this detector matches the threat pattern
		matches, err := matchesThreatCriteria(def.ThreatMetadata, propertyPath, evtFlag.operator, evtFlag.values)
		if err != nil {
			return nil, err
		}

		if matches {
			// Get the event name and ID for this detector
			eventName := def.ProducedEvent.Name
			if eventID, ok := eventNamesToID[eventName]; ok {
				matchingEvents[eventID] = eventName
			}
		}
	}

	// If no detectors matched, return an error
	if len(matchingEvents) == 0 {
		return nil, errfmt.Errorf("no detectors match threat pattern: %s", evtFlag.full)
	}

	return matchingEvents, nil
}

// matchesThreatCriteria checks if threat metadata matches the given criteria
// propertyPath can be: "severity", "name", "mitre.technique", "mitre.tactic"
func matchesThreatCriteria(threat *v1beta1.Threat, propertyPath, operator, value string) (bool, error) {
	switch propertyPath {
	case "severity":
		return matchSeverity(threat.Severity, operator, value)

	case "mitre.technique":
		// Match MITRE technique ID (e.g., T1055)
		if threat.Mitre == nil || threat.Mitre.Technique == nil {
			return false, nil
		}
		return matchString(threat.Mitre.Technique.Id, operator, value)

	case "mitre.tactic":
		// Match MITRE tactic name (e.g., "Defense Evasion")
		if threat.Mitre == nil || threat.Mitre.Tactic == nil {
			return false, nil
		}
		return matchString(threat.Mitre.Tactic.Name, operator, value)

	case "name":
		// Match threat name
		return matchString(threat.Name, operator, value)

	default:
		return false, errfmt.Errorf("unsupported threat property: %s (supported: severity, name, mitre.technique, mitre.tactic)", propertyPath)
	}
}

// matchSeverity checks if a severity value matches the given criteria
// Supports both numeric values (0-4) and string names (info, low, medium, high, critical)
// Supports operators: =, !=, <, >, <=, >=
func matchSeverity(severity v1beta1.Severity, operator, value string) (bool, error) {
	// Parse target severity value (can be numeric or string)
	var targetSeverity int32

	switch strings.ToLower(value) {
	case "info", "0":
		targetSeverity = 0
	case "low", "1":
		targetSeverity = 1
	case "medium", "2":
		targetSeverity = 2
	case "high", "3":
		targetSeverity = 3
	case "critical", "4":
		targetSeverity = 4
	default:
		return false, errfmt.Errorf("invalid severity value: %s (must be info/low/medium/high/critical or 0-4)", value)
	}

	severityValue := int32(severity)

	switch operator {
	case "=":
		return severityValue == targetSeverity, nil
	case "!=":
		return severityValue != targetSeverity, nil
	case "<":
		return severityValue < targetSeverity, nil
	case ">":
		return severityValue > targetSeverity, nil
	case "<=":
		return severityValue <= targetSeverity, nil
	case ">=":
		return severityValue >= targetSeverity, nil
	default:
		return false, errfmt.Errorf("unsupported operator for severity: %s", operator)
	}
}

// matchString checks if a string value matches the given criteria
// Supports operators: = (equality), != (inequality)
func matchString(actual, operator, pattern string) (bool, error) {
	switch operator {
	case "=":
		return actual == pattern, nil

	case "!=":
		return actual != pattern, nil

	default:
		return false, errfmt.Errorf("unsupported operator for string matching: %s", operator)
	}
}
