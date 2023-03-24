package flags

import (
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
)

// FilterMap holds pre-parsed filter flag fields
type FilterMap map[int][]*filterFlag

// filterFlag holds pre-parsed filter flag fields
type filterFlag struct {
	full              string
	filterName        string
	operatorAndValues string
	// policy
	policyIdx  int
	policyName string
}

// parseFilterFlag parses a filter flag and returns a filterFlag struct with
// pre-parsed fields, or an error if the flag is invalid.
// policyIdx and policyName are always set to 0 and "" respectively, since this
// function is used for parsing cli filter flags only.
// For policy workloads, see PrepareFilterMapFromPolicies.
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
			policyIdx:         0,
			policyName:        "",
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
		policyIdx:         0,
		policyName:        "",
	}, nil
}
