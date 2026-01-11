package flags

import (
	"strings"

	"github.com/aquasecurity/tracee/pkg/events"
)

// EventListFilters holds filter configuration for listing events.
// Multiple filters are combined with AND logic.
// Comma-separated values within a filter are combined with OR logic.
type EventListFilters struct {
	Tags       []string // Filter by tags/sets (from GetSets())
	Types      []string // Filter by event type (syscall, detector, network)
	Severities []string // Filter by threat severity (info, low, medium, high, critical)
	Names      []string // Filter by name pattern (supports * wildcards)
	Techniques []string // Filter by MITRE technique ID (e.g., T1055)
	Tactics    []string // Filter by MITRE tactic name (e.g., Execution)
}

// ParseEventFilters parses positional arguments into EventListFilters.
// Supported patterns:
//   - eventname       : exact event name match
//   - open*           : wildcard pattern match
//   - tag=fs          : filter by tag/set
//   - tag=fs,network  : filter by tag (OR within comma-separated values)
//   - type=syscall    : filter by event type
//   - threat.severity=critical : filter by threat severity
//   - threat.mitre.technique=T1055 : filter by MITRE technique
//   - threat.mitre.tactic=Execution : filter by MITRE tactic
//
// Multiple arguments are combined with AND logic.
func ParseEventFilters(args []string) EventListFilters {
	filters := EventListFilters{}

	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}

		// Check for key=value patterns
		if idx := strings.Index(arg, "="); idx > 0 {
			key := strings.ToLower(arg[:idx])
			value := arg[idx+1:]

			switch key {
			case "tag", "set":
				filters.Tags = append(filters.Tags, value)
			case "type":
				filters.Types = append(filters.Types, value)
			case "threat.severity":
				filters.Severities = append(filters.Severities, value)
			case "threat.mitre.technique":
				filters.Techniques = append(filters.Techniques, value)
			case "threat.mitre.tactic":
				filters.Tactics = append(filters.Tactics, value)
			default:
				// Unknown key=value, treat as name pattern
				filters.Names = append(filters.Names, arg)
			}
		} else {
			// No equals sign - treat as event name or wildcard pattern
			filters.Names = append(filters.Names, arg)
		}
	}

	return filters
}

// HasFilters returns true if any filters are configured.
func (f EventListFilters) HasFilters() bool {
	return len(f.Tags) > 0 || len(f.Types) > 0 || len(f.Severities) > 0 ||
		len(f.Names) > 0 || len(f.Techniques) > 0 || len(f.Tactics) > 0
}

// MatchesEvent returns true if the event definition matches all configured filters.
// Multiple filters are AND'd together.
// Comma-separated values within a filter are OR'd together.
func (f EventListFilters) MatchesEvent(def events.Definition) bool {
	// If no filters, match everything
	if !f.HasFilters() {
		return true
	}

	// All filter groups must match (AND between groups)
	if len(f.Tags) > 0 && !f.matchesTags(def) {
		return false
	}
	if len(f.Types) > 0 && !f.matchesTypes(def) {
		return false
	}
	if len(f.Names) > 0 && !f.matchesNames(def) {
		return false
	}
	if len(f.Severities) > 0 && !f.matchesSeverities(def) {
		return false
	}
	if len(f.Techniques) > 0 && !f.matchesTechniques(def) {
		return false
	}
	if len(f.Tactics) > 0 && !f.matchesTactics(def) {
		return false
	}

	return true
}

// matchesTags checks if the event matches the tag filters.
// Multiple tag filters are AND'd: event must match ALL filter groups.
// Comma-separated values within a filter are OR'd: event must match ANY value in group.
func (f EventListFilters) matchesTags(def events.Definition) bool {
	eventTags := def.GetSets()

	// Each tag filter must match (AND between filters)
	for _, tagGroup := range f.Tags {
		// Split comma-separated values (OR within group)
		values := splitAndTrim(tagGroup)
		if !matchesAnyTag(eventTags, values) {
			return false
		}
	}
	return true
}

// matchesTypes checks if the event matches the type filters.
// Multiple type filters are AND'd.
// Comma-separated values within a filter are OR'd.
func (f EventListFilters) matchesTypes(def events.Definition) bool {
	// Each type filter must match (AND between filters)
	for _, typeGroup := range f.Types {
		values := splitAndTrim(typeGroup)
		if !matchesAnyType(def, values) {
			return false
		}
	}
	return true
}

// matchesNames checks if the event matches the name filters.
// Multiple name filters are AND'd.
// Comma-separated values within a filter are OR'd.
func (f EventListFilters) matchesNames(def events.Definition) bool {
	eventName := def.GetName()

	// Each name filter must match (AND between filters)
	for _, nameGroup := range f.Names {
		values := splitAndTrim(nameGroup)
		if !matchesAnyPattern(eventName, values) {
			return false
		}
	}
	return true
}

// matchesSeverities checks if the event matches the severity filters.
func (f EventListFilters) matchesSeverities(def events.Definition) bool {
	props := def.GetProperties()
	if props == nil {
		return false
	}

	severityVal, ok := props["Severity"]
	if !ok {
		return false
	}

	eventSeverity, ok := severityVal.(string)
	if !ok {
		return false
	}

	for _, sevGroup := range f.Severities {
		values := splitAndTrim(sevGroup)
		if !matchesAnyString(eventSeverity, values) {
			return false
		}
	}
	return true
}

// matchesTechniques checks if the event matches the MITRE technique filters.
func (f EventListFilters) matchesTechniques(def events.Definition) bool {
	props := def.GetProperties()
	if props == nil {
		return false
	}

	techID, ok := props["mitre_technique_id"]
	if !ok {
		return false
	}

	eventTechniqueID, ok := techID.(string)
	if !ok {
		return false
	}

	for _, techGroup := range f.Techniques {
		values := splitAndTrim(techGroup)
		if !matchesAnyString(eventTechniqueID, values) {
			return false
		}
	}
	return true
}

// matchesTactics checks if the event matches the MITRE tactic filters.
func (f EventListFilters) matchesTactics(def events.Definition) bool {
	props := def.GetProperties()
	if props == nil {
		return false
	}

	tacticName, ok := props["mitre_tactic_name"]
	if !ok {
		return false
	}

	eventTacticName, ok := tacticName.(string)
	if !ok {
		return false
	}

	for _, tacticGroup := range f.Tactics {
		values := splitAndTrim(tacticGroup)
		if !matchesAnyString(eventTacticName, values) && !matchesAnyString(normalizeTactic(eventTacticName), normalizeTactics(values)) {
			return false
		}
	}
	return true
}

// Helper functions

func matchesAnyTag(eventTags []string, filterTags []string) bool {
	for _, filterTag := range filterTags {
		for _, eventTag := range eventTags {
			if strings.EqualFold(eventTag, filterTag) {
				return true
			}
		}
	}
	return false
}

func matchesAnyType(def events.Definition, types []string) bool {
	for _, t := range types {
		switch strings.ToLower(t) {
		case "syscall":
			if def.IsSyscall() {
				return true
			}
		case "detector":
			if def.IsDetector() {
				return true
			}
		case "network":
			if def.IsNetwork() {
				return true
			}
		}
	}
	return false
}

func matchesAnyPattern(name string, patterns []string) bool {
	for _, pattern := range patterns {
		if matchPattern(name, pattern) {
			return true
		}
	}
	return false
}

func matchPattern(name, pattern string) bool {
	pattern = strings.ToLower(pattern)
	name = strings.ToLower(name)

	// No wildcard - exact match
	if !strings.Contains(pattern, "*") {
		return name == pattern
	}

	// Contains match: *pattern*
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		inner := strings.Trim(pattern, "*")
		return strings.Contains(name, inner)
	}

	// Prefix match: pattern*
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(name, prefix)
	}

	// Suffix match: *pattern
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(name, suffix)
	}

	return false
}

func matchesAnyString(value string, filterValues []string) bool {
	for _, filterVal := range filterValues {
		if strings.EqualFold(value, filterVal) {
			return true
		}
	}
	return false
}

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func normalizeTactic(tactic string) string {
	n := strings.ToLower(strings.TrimSpace(tactic))
	n = strings.ReplaceAll(n, "_", " ")
	n = strings.ReplaceAll(n, "-", " ")
	n = strings.Join(strings.Fields(n), " ")
	return n
}

func normalizeTactics(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, normalizeTactic(v))
	}
	return out
}
