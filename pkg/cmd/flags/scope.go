package flags

import (
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
)

func scopeHelp() string {
	return `The scope flag (--scope) filters events based on process and container context.
All scope filters are ANDed together - events must match ALL specified conditions.

Filter Types:
1. Numerical Comparisons ('=', '!=', '<', '>'):
   - uid, pid: Process identifiers
   - mntns, pidns: Namespace identifiers
   Note: Operators '<' and '>' must be escaped with quotes: 'uid>-1'

2. String Comparisons ('=', '!='):
   - uts: UTS namespace name
   - comm: Process command name
   - container: Container ID
   - executable: Full path to executable
   Note: Multiple values can be comma-separated with '=' (OR) or '!=' (AND)

3. Boolean Flags:
   - container: Match containerized processes
   - not-container: Match host processes
   - follow: Include child processes

Special Values:
- 'new': For container and pid filters to match newly created ones
- 'host:' prefix: For executable paths in host namespace
- namespace ID prefix: For executable paths in specific mount namespace

Examples:
  Process Filters:
    --scope pid=new                                   | trace new processes
    --scope pid=509,1709                              | trace PIDs 509 or 1709
    --scope 'uid>-1' --scope 'pid<1000'               | trace non-root processes with PID < 1000
    --scope comm=ls                                   | trace 'ls' command
    --scope executable=/usr/bin/ls                    | trace specific executable
    --scope comm=bash --scope follow                  | trace bash and its child processes

  Container Filters:
    --scope container=new                             | trace new containers
    --scope container=ab355bc4dd554                   | trace specific container
    --scope container                                 | trace all containers
    --scope not-container                             | trace host only

  Namespace Filters:
    --scope mntns=4026531839                          | trace specific mount namespace
    --scope pidns!=4026531835                         | exclude specific PID namespace
    --scope executable=host:/usr/bin/ls               | trace ls in host mount namespace
    --scope executable=4026532447:/usr/bin/ls         | trace ls in specific mount namespace

  Process Tree:
    --scope tree=476164                               | trace process and its descendants
    --scope tree=3212,5200 --scope tree!=3215         | trace descendants of 3212 or 5200, except 3215's
`
}

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
