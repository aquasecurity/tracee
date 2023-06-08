package flags

import (
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
)

// PolicyFilterMap maps policy id to its pre-parsed filter flag fields
type PolicyFilterMap map[int]policyFilters

// policyFilters holds pre-parsed filter flag fields of one policy
type policyFilters struct {
	policyName  string
	filterFlags []*filterFlag
}

// filterFlag holds pre-parsed filter flag fields
type filterFlag struct {
	full              string
	filterName        string
	operatorAndValues string
}

// parseFilterFlag parses a filter flag and returns a filterFlag struct with
// pre-parsed fields, or an error if the flag is invalid.
func parseFilterFlag(flag string) (*filterFlag, error) {
	if len(flag) == 0 {
		return nil, errfmt.WrapError(InvalidFlagEmpty())
	}

	operatorIdx := strings.IndexAny(flag, "=!<>")

	if operatorIdx == -1 || // no operator, as a set flag
		(operatorIdx == 0 && flag[0] == '!') { // negation, as an unset flag
		return &filterFlag{
			full:              flag,
			filterName:        flag,
			operatorAndValues: "",
		}, nil
	}

	filterName := flag[:operatorIdx]
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

	return &filterFlag{
		full:              flag,
		filterName:        filterName,
		operatorAndValues: operatorAndValues,
	}, nil
}
