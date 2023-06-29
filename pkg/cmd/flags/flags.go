package flags

import (
	"strings"
)

// hasLeadingOrTrailingWhitespace checks if the string has leading or trailing whitespace.
func hasLeadingOrTrailingWhitespace(s string) bool {
	if strings.HasPrefix(s, " ") || strings.HasPrefix(s, "\t") ||
		strings.HasSuffix(s, " ") || strings.HasSuffix(s, "\t") {
		return true
	}

	return false
}

// isFlagOperatorValid checks if the operator is valid.
func isFlagOperatorValid(operator string) bool {
	switch operator {
	case "=", "!=", "<", "<=", ">", ">=":
		return true
	default:
		return false
	}
}

type operatorAndValuesParts struct {
	operatorAndValues string
	operator          string
	values            string
}

// getOperatorAndValuesParts splits a flag into its operator and values parts, validating them.
// Valid formats: "xxxx=xxxx", "xxxx!=xxxx", "xxxx<xxxx", "xxxx<=xxxx", "xxxx>xxxx", "xxxx>=xxxx".
//
// It is used by parseScopeFlag and parseEventFlag.
func getOperatorAndValuesParts(flag string, operatorIdx int) (operatorAndValuesParts, error) {
	operatorAndValues := flag[operatorIdx:]
	if len(operatorAndValues) < 2 {
		return operatorAndValuesParts{}, InvalidFilterFlagFormat(flag)
	}

	// get last idx of any operator, when a 2 char operator, e.g. "!="
	operatorEndIdx := strings.LastIndexAny(operatorAndValues[:2], "=!<>")
	if operatorEndIdx == -1 {
		operatorEndIdx = operatorIdx
	}
	// flag is invalid when there is no more chars after operator
	if operatorEndIdx+1 >= len(operatorAndValues) {
		return operatorAndValuesParts{}, InvalidFilterFlagFormat(flag)
	}

	operator := operatorAndValues[:operatorEndIdx+1]
	if !isFlagOperatorValid(operator) {
		return operatorAndValuesParts{}, InvalidFlagOperator(flag)
	}

	values := operatorAndValues[operatorEndIdx+1:]
	if hasLeadingOrTrailingWhitespace(values) {
		return operatorAndValuesParts{}, InvalidFlagValue(flag)
	}

	return operatorAndValuesParts{
		operatorAndValues: operatorAndValues,
		operator:          operator,
		values:            values,
	}, nil
}
