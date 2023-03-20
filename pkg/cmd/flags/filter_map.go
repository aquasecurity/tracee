package flags

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/policy"
)

// FilterMap holds pre-parsed filter flag fields
type FilterMap map[int][]*filterFlag

// filterFlag holds pre-parsed filter flag fields
type filterFlag struct {
	full              string
	filterName        string
	operatorAndValues string
	policyIdx         int
}

func parseFilterFlag(flag string) (*filterFlag, error) {
	var (
		policyID          int // stores the parsed policy index, not its flag position
		filterName        string
		operatorAndValues string

		policyEndIdx     int // stores ':' flag index (end of the policy value)
		filterNameIdx    int
		filterNameEndIdx int
		operatorIdx      int
		err              error
	)

	policyEndIdx = strings.Index(flag, ":")
	operatorIdx = strings.IndexAny(flag, "=!<>")

	if policyEndIdx == -1 && operatorIdx == -1 {
		return &filterFlag{
			full:              flag,
			filterName:        flag,
			operatorAndValues: "",
			policyIdx:         policyID,
		}, nil
	}

	if operatorIdx != -1 {
		operatorAndValues = flag[operatorIdx:]
		filterNameEndIdx = operatorIdx
	} else {
		operatorIdx = len(flag) - 1
		filterNameEndIdx = len(flag)
	}

	// check operators
	if len(operatorAndValues) == 1 ||
		operatorAndValues == "!=" ||
		operatorAndValues == "<=" ||
		operatorAndValues == ">=" {

		return nil, filters.InvalidExpression(flag)
	}

	if policyEndIdx != -1 && policyEndIdx < operatorIdx {
		// parse its ID
		policyID, err = strconv.Atoi(flag[:policyEndIdx])
		if err != nil {
			return nil, filters.InvalidPolicy(fmt.Sprintf("%s - %s", flag, err))
		}

		// now consider it as a policy index
		policyID--
		if policyID < 0 || policyID > policy.MaxPolicies-1 {
			return nil, filters.InvalidPolicy(fmt.Sprintf("%s - policies must be between 1 and %d", flag, policy.MaxPolicies))
		}

		filterNameIdx = policyEndIdx + 1
	}

	if len(operatorAndValues) >= 2 &&
		operatorAndValues[0] == '!' &&
		operatorAndValues[1] != '=' {

		filterName = flag[filterNameIdx:]
		if strings.HasSuffix(filterName, "follow") ||
			strings.HasSuffix(filterName, "container") {

			return &filterFlag{
				full:              flag,
				filterName:        filterName,
				operatorAndValues: "",
				policyIdx:         policyID,
			}, nil
		}

		return nil, filters.InvalidExpression(flag)
	}

	// parse filter name
	filterName = flag[filterNameIdx:filterNameEndIdx]

	return &filterFlag{
		full:              flag,
		filterName:        filterName,
		operatorAndValues: operatorAndValues,
		policyIdx:         policyID,
	}, nil
}
