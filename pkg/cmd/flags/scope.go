package flags

import (
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
)

// PolicyScopeMap maps policy id to its pre-parsed scope flag fields
type PolicyScopeMap map[int]policyScopes

// policyScopes holds pre-parsed scope flag fields of one policy
type policyScopes struct {
	policyName string
	scopeFlags []scopeFlag
}

// scopeFlag holds pre-parsed scope flag fields
type scopeFlag struct {
	full              string
	scopeFilter       string
	scopeName         string
	operator          string
	values            string
	operatorAndValues string
}

func PrepareScopeMapFromFlags(filtersArr []string) (PolicyScopeMap, error) {
	// parse and store scope flags
	var filterFlags []scopeFlag
	for _, filter := range filtersArr {
		parsed, err := parseScopeFlag(filter)
		if err != nil {
			return nil, err
		}

		filterFlags = append(filterFlags, parsed)
	}

	filterMap := make(PolicyScopeMap)
	filterMap[0] = policyScopes{scopeFlags: filterFlags}

	return filterMap, nil
}

// parseScopeFlag parses a scope flag and returns a scopeFlag struct with
// pre-parsed fields, or an error if the flag is invalid.
func parseScopeFlag(flag string) (scopeFlag, error) {
	if flag == "" {
		return scopeFlag{}, errfmt.WrapError(InvalidFlagEmpty())
	}

	// get first idx of any operator
	operatorIdx := strings.IndexAny(flag, "=!<>")
	if operatorIdx == -1 || // no operator, as a set flag
		(operatorIdx == 0 && flag[0] == '!') { // negation, as an unset flag
		if hasLeadingOrTrailingWhitespace(flag) {
			return scopeFlag{}, errfmt.WrapError(InvalidFilterFlagFormat(flag))
		}

		return scopeFlag{
			full:      flag,
			scopeName: flag,
		}, nil
	}

	// validate scope name
	scopeName := flag[:operatorIdx]
	if hasLeadingOrTrailingWhitespace(scopeName) {
		return scopeFlag{}, errfmt.WrapError(InvalidFilterFlagFormat(flag))
	}

	// validate operator and values
	opAndValParts, err := getOperatorAndValuesParts(flag, operatorIdx)
	if err != nil {
		return scopeFlag{}, errfmt.WrapError(err)
	}

	return scopeFlag{
		full:              flag,                            // "binary=host:/usr/bin/ls"
		scopeName:         scopeName,                       // "binary"
		operator:          opAndValParts.operator,          // "="
		values:            opAndValParts.values,            // "host:/usr/bin/ls"
		operatorAndValues: opAndValParts.operatorAndValues, // "=host:/usr/bin/ls"
	}, nil
}
