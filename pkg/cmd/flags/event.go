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
	eventFlags []*eventFlag
}

// eventFlag holds pre-parsed event flag fields
type eventFlag struct {
	full              string
	eventName         string
	filter            string
}

func PrepareEventMapFromFlags(eventsArr []string) (PolicyEventMap, error) {
	// parse and store events
	var eventFlags []*eventFlag
	for _, event := range eventsArr {
		parsed, err := parseEventFlag(event)
		if err != nil {
			return nil, err
		}

		eventFlags = append(eventFlags, parsed)
	}

	eventMap := make(PolicyEventMap)
	eventMap[0] = policyEvents{eventFlags: eventFlags}

	return eventMap, nil
}

// parseEventFlag parses an event flag and returns an eventFlag struct with
// pre-parsed fields, or an error if the flag is invalid.
func parseEventFlag(flag string) (*eventFlag, error) {
	if len(flag) == 0 {
		return nil, errfmt.WrapError(InvalidFlagEmpty())
	}

	// values := strings.Split(flag.full, ",")

	// for i := range values {
	// 	// todo
	// }

	// todo: we can prbably remove all the below
	operatorIdx := strings.IndexAny(flag, "=!")

	if operatorIdx == -1 || // no operator, as a set flag
		(operatorIdx == 0 && flag[0] == '!') { // negation, as an unset flag

		return &eventFlag{
			full:              flag,
			eventName:         flag,
			filter:            "",
		}, nil
	}

	eventName := flag[:operatorIdx]
	operatorAndValues := flag[operatorIdx:]

	operatorEndIdx := strings.LastIndexAny(operatorAndValues, "=!<>")
	operator := operatorAndValues[:operatorEndIdx+1]
	switch operator {
	case "=", "!=", "<", "<=", ">", ">=":
		// valid operators
	default:
		return nil, errfmt.WrapError(InvalidFlagOperator(flag))
	}

	value := operatorAndValues[operatorEndIdx+1:]
	if len(value) == 0 {
		return nil, errfmt.WrapError(InvalidFlagValue(flag))
	}

	if strings.HasPrefix(value, " ") || strings.HasPrefix(value, "\t") ||
		strings.HasSuffix(value, " ") || strings.HasSuffix(value, "\t") {

		return nil, errfmt.WrapError(InvalidFlagValue(flag))
	}

	return &eventFlag{
		full:              flag,
		eventName:         eventName,
		filter:            "",
	}, nil
}
