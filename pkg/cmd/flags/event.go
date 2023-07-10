package flags

import (
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
)

// PolicyEventMap maps policy id to its pre-parsed event flag fields
type PolicyEventMap map[int]policyEvents

// policyEvents holds pre-parsed event flag fields of one policy
type policyEvents struct {
	policyName string
	eventFlags []eventFlag
}

// eventFlag holds pre-parsed event flag fields
type eventFlag struct {
	full              string
	eventFilter       string
	eventName         string
	eventOptionType   string
	eventOptionName   string
	operator          string
	values            string
	operatorAndValues string
	filter            string
}

func PrepareEventMapFromFlags(eventsArr []string) (PolicyEventMap, error) {
	// parse and store events flags
	var evtFlags []eventFlag
	for _, evtFlag := range eventsArr {
		parsed, err := parseEventFlag(evtFlag)
		if err != nil {
			return nil, err
		}

		evtFlags = append(evtFlags, parsed)
	}

	eventMap := make(PolicyEventMap)
	eventMap[0] = policyEvents{eventFlags: evtFlags}

	return eventMap, nil
}

// parseEventFlag parses an event flag and returns an eventFlag struct with
// pre-parsed fields, or an error if the flag is invalid.
func parseEventFlag(flag string) (eventFlag, error) {
	if flag == "" {
		return eventFlag{}, errfmt.WrapError(InvalidFlagEmpty())
	}

	// get first idx of any operator
	operatorIdx := strings.IndexAny(flag, "=!<>")
	if operatorIdx == -1 { // no operator
		// "openat.context.container" edge case
		if strings.Contains(flag, ".") {
			evtParts, err := getEventFilterParts(flag, flag)
			if err != nil {
				return eventFlag{}, errfmt.WrapError(err)
			}

			return eventFlag{
				full:            flag,
				eventFilter:     flag,
				eventName:       evtParts.name,
				eventOptionType: evtParts.optType,
				eventOptionName: evtParts.optName,
			}, nil
		}

		if hasLeadingOrTrailingWhitespace(flag) {
			return eventFlag{}, errfmt.WrapError(InvalidFilterFlagFormat(flag))
		}

		return eventFlag{
			full:      flag,
			eventName: flag,
		}, nil
	}

	// validate event filter
	evtFilter := flag[:operatorIdx]
	evtParts, err := getEventFilterParts(evtFilter, flag)
	if err != nil {
		return eventFlag{}, errfmt.WrapError(err)
	}
	filter := flag[len(evtParts.name)+1:]

	// validate operator and values
	opAndValParts, err := getOperatorAndValuesParts(flag, operatorIdx)
	if err != nil {
		return eventFlag{}, errfmt.WrapError(err)
	}

	return eventFlag{
		full:              flag,                            // "openat.args.pathname=/etc/*"
		eventFilter:       evtFilter,                       // "openat.args.pathname"
		eventName:         evtParts.name,                   // "openat"
		eventOptionType:   evtParts.optType,                // "args"
		eventOptionName:   evtParts.optName,                // "pathname"
		operator:          opAndValParts.operator,          // "="
		values:            opAndValParts.values,            // "/etc/*"
		operatorAndValues: opAndValParts.operatorAndValues, // "=/etc/*"
		filter:            filter,                          // "args.pathname=/etc/*"
	}, nil
}

type filterOptParts struct {
	name    string
	optType string
	optName string
}

// getEventFilterParts splits an event filter into its parts, validating them.
// Valid formats: "xxxx.xxxx", "xxxx.xxxx.xxxx".
func getEventFilterParts(filter, flag string) (filterOptParts, error) {
	filterParts := strings.Split(filter, ".")

	if filterParts[0] == "" || len(filterParts) < 2 || filterParts[1] == "" || len(filterParts) > 3 {
		return filterOptParts{}, InvalidFilterFlagFormat(flag)
	}
	name := filterParts[0]
	optType := filterParts[1]
	optName := ""
	if len(filterParts) == 3 {
		optName = filterParts[2]
		if optName == "" {
			return filterOptParts{}, InvalidFilterFlagFormat(flag)
		}
	}

	if hasLeadingOrTrailingWhitespace(name) ||
		hasLeadingOrTrailingWhitespace(optType) ||
		hasLeadingOrTrailingWhitespace(optName) {
		return filterOptParts{}, InvalidFilterFlagFormat(flag)
	}

	return filterOptParts{
		name:    name,
		optType: optType,
		optName: optName,
	}, nil
}
