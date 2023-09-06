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

	// get first idx of any expression operator (=, !=, <, >, <=, >=)
	operatorIdx := strings.IndexAny(flag, "=!<>")

	//
	// without expression operator
	//

	if operatorIdx == -1 { // no expression operator
		if hasLeadingOrTrailingWhitespace(flag) {
			return scopeFlag{}, errfmt.WrapError(InvalidFilterFlagFormat(flag))
		}

		// unset flag
		unsetPrefix := "not-"
		if strings.HasPrefix(flag, unsetPrefix) {
			if len(flag) == len(unsetPrefix) {
				return scopeFlag{}, errfmt.WrapError(InvalidFilterFlagFormat(flag))
			}

			name := flag[len(unsetPrefix):]
			if hasLeadingOrTrailingWhitespace(name) {
				return scopeFlag{}, errfmt.WrapError(InvalidFilterFlagFormat(flag))
			}

			return scopeFlag{
				full:      flag,
				scopeName: name,
				operator:  unsetPrefix[:len(unsetPrefix)-1],
			}, nil
		}

		// set flag
		return scopeFlag{
			full:      flag,
			scopeName: flag,
		}, nil
	}

	//
	// with expression operator
	//

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
		full:              flag,                            // "executable=host:/usr/bin/ls"
		scopeName:         scopeName,                       // "executable"
		operator:          opAndValParts.operator,          // "="
		values:            opAndValParts.values,            // "host:/usr/bin/ls"
		operatorAndValues: opAndValParts.operatorAndValues, // "=host:/usr/bin/ls"
	}, nil
}
