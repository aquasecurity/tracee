package yaml

import (
	"path/filepath"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// registerStringFunctions registers all string utility CEL functions
// Returns CEL environment options for string utility functions
func registerStringFunctions() []cel.EnvOption {
	return []cel.EnvOption{
		// split(string, delimiter) -> list<string>
		cel.Function("split",
			cel.Overload("split_string_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.ListType(cel.StringType),
				cel.BinaryBinding(createSplitBinding),
			),
		),

		// join(list<string>, delimiter) -> string
		cel.Function("join",
			cel.Overload("join_list_string",
				[]*cel.Type{cel.ListType(cel.StringType), cel.StringType},
				cel.StringType,
				cel.BinaryBinding(createJoinBinding),
			),
		),

		// trim(string) -> string (removes leading and trailing whitespace)
		cel.Function("trim",
			cel.Overload("trim_string",
				[]*cel.Type{cel.StringType},
				cel.StringType,
				cel.UnaryBinding(createTrimBinding),
			),
		),

		// replace(string, old, new) -> string (replaces all occurrences)
		cel.Function("replace",
			cel.Overload("replace_string_string_string",
				[]*cel.Type{cel.StringType, cel.StringType, cel.StringType},
				cel.StringType,
				cel.FunctionBinding(createReplaceBinding),
			),
		),

		// upper(string) -> string (converts to uppercase)
		cel.Function("upper",
			cel.Overload("upper_string",
				[]*cel.Type{cel.StringType},
				cel.StringType,
				cel.UnaryBinding(createUpperBinding),
			),
		),

		// lower(string) -> string (converts to lowercase)
		cel.Function("lower",
			cel.Overload("lower_string",
				[]*cel.Type{cel.StringType},
				cel.StringType,
				cel.UnaryBinding(createLowerBinding),
			),
		),

		// basename(string) -> string (returns last element of path)
		cel.Function("basename",
			cel.Overload("basename_string",
				[]*cel.Type{cel.StringType},
				cel.StringType,
				cel.UnaryBinding(createBasenameBinding),
			),
		),

		// dirname(string) -> string (returns directory portion of path)
		cel.Function("dirname",
			cel.Overload("dirname_string",
				[]*cel.Type{cel.StringType},
				cel.StringType,
				cel.UnaryBinding(createDirnameBinding),
			),
		),
	}
}

// createSplitBinding creates a binding for split(string, delimiter)
func createSplitBinding(lhs, rhs ref.Val) ref.Val {
	str, ok := lhs.Value().(string)
	if !ok {
		return types.NewErr("split: first argument must be a string")
	}

	delimiter, ok := rhs.Value().(string)
	if !ok {
		return types.NewErr("split: second argument must be a string")
	}

	parts := strings.Split(str, delimiter)
	// Convert Go slice to CEL list using NativeToValue
	return types.DefaultTypeAdapter.NativeToValue(parts)
}

// createJoinBinding creates a binding for join(list<string>, delimiter)
func createJoinBinding(lhs, rhs ref.Val) ref.Val {
	// Convert CEL list value to Go slice
	// CEL lists can be represented in different ways, so we need to handle multiple cases
	var parts []string

	// First, try to get the native value
	listVal := lhs.Value()

	// Handle direct []string
	if strSlice, ok := listVal.([]string); ok {
		parts = strSlice
	} else if ifaceSlice, ok := listVal.([]interface{}); ok {
		// Handle []interface{} and extract strings
		for _, item := range ifaceSlice {
			str, ok := item.(string)
			if !ok {
				return types.NewErr("join: list must contain strings, got %T", item)
			}
			parts = append(parts, str)
		}
	} else if refValSlice, ok := listVal.([]ref.Val); ok {
		// Handle []ref.Val (CEL's internal list representation)
		for _, item := range refValSlice {
			if strVal, ok := item.(types.String); ok {
				parts = append(parts, string(strVal))
				continue
			}
			str, ok := item.Value().(string)
			if !ok {
				return types.NewErr("join: list must contain strings, got %T", item.Value())
			}
			parts = append(parts, str)
		}
	} else {
		// Try to convert using CEL's type adapter (handles CEL list types)
		nativeVal := types.DefaultTypeAdapter.NativeToValue(listVal)
		if nativeVal == nil {
			return types.NewErr("join: first argument must be a list")
		}
		if nativeList, ok := nativeVal.Value().([]string); ok {
			parts = nativeList
		} else if nativeList, ok := nativeVal.Value().([]interface{}); ok {
			for _, item := range nativeList {
				str, ok := item.(string)
				if !ok {
					return types.NewErr("join: list must contain strings, got %T", item)
				}
				parts = append(parts, str)
			}
		} else {
			// Last resort: try to iterate if it's a CEL list type
			// Check if it implements the list interface by trying Value() again
			return types.NewErr("join: first argument must be a list of strings, got %T", listVal)
		}
	}

	delimiter, ok := rhs.Value().(string)
	if !ok {
		return types.NewErr("join: second argument must be a string")
	}

	return types.String(strings.Join(parts, delimiter))
}

// createTrimBinding creates a binding for trim(string)
func createTrimBinding(arg ref.Val) ref.Val {
	str, ok := arg.Value().(string)
	if !ok {
		return types.NewErr("trim: argument must be a string")
	}

	return types.String(strings.TrimSpace(str))
}

// createReplaceBinding creates a binding for replace(string, old, new)
func createReplaceBinding(args ...ref.Val) ref.Val {
	if len(args) != 3 {
		return types.NewErr("replace: requires 3 arguments (string, old, new)")
	}

	str, ok := args[0].Value().(string)
	if !ok {
		return types.NewErr("replace: first argument must be a string")
	}

	oldStr, ok := args[1].Value().(string)
	if !ok {
		return types.NewErr("replace: second argument must be a string")
	}

	newStr, ok := args[2].Value().(string)
	if !ok {
		return types.NewErr("replace: third argument must be a string")
	}

	return types.String(strings.ReplaceAll(str, oldStr, newStr))
}

// createUpperBinding creates a binding for upper(string)
func createUpperBinding(arg ref.Val) ref.Val {
	str, ok := arg.Value().(string)
	if !ok {
		return types.NewErr("upper: argument must be a string")
	}

	return types.String(strings.ToUpper(str))
}

// createLowerBinding creates a binding for lower(string)
func createLowerBinding(arg ref.Val) ref.Val {
	str, ok := arg.Value().(string)
	if !ok {
		return types.NewErr("lower: argument must be a string")
	}

	return types.String(strings.ToLower(str))
}

// createBasenameBinding creates a binding for basename(string)
func createBasenameBinding(arg ref.Val) ref.Val {
	str, ok := arg.Value().(string)
	if !ok {
		return types.NewErr("basename: argument must be a string")
	}

	return types.String(filepath.Base(str))
}

// createDirnameBinding creates a binding for dirname(string)
func createDirnameBinding(arg ref.Val) ref.Val {
	str, ok := arg.Value().(string)
	if !ok {
		return types.NewErr("dirname: argument must be a string")
	}

	return types.String(filepath.Dir(str))
}
