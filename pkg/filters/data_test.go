package filters

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters/sets"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestDataFilterClone(t *testing.T) {
	t.Parallel()

	filter := NewDataFilter()
	err := filter.Parse(events.Read, "fd", "=dataval")
	require.NoError(t, err)

	copy := filter.Clone()

	opt1 := cmp.AllowUnexported(
		DataFilter{},
		StringFilter{},
		sets.PrefixSet{},
		sets.SuffixSet{},
		KernelDataFilter{},
	)
	opt2 := cmp.FilterPath(
		func(p cmp.Path) bool {
			// ignore the function field
			// https://cs.opensource.google/go/go/+/refs/tags/go1.22.0:src/reflect/deepequal.go;l=187
			return p.Last().Type().Kind() == reflect.Func
		},
		cmp.Ignore(),
	)

	if !cmp.Equal(filter, copy, opt1, opt2) {
		diff := cmp.Diff(filter, copy, opt1, opt2)
		t.Errorf("Clone did not produce an identical copy\ndiff: %s", diff)
	}

	// ensure that changes to the copy do not affect the original
	err = copy.Parse(events.Read, "buf", "=dataval")
	require.NoError(t, err)
	if cmp.Equal(filter, copy, opt1, opt2) {
		t.Errorf("Changes to copied filter affected the original %+v", filter)
	}
}

func newArgument(argName, argType string, argValue interface{}) trace.Argument {
	return trace.Argument{
		ArgMeta: trace.ArgMeta{
			Name: argName,
			Type: argType,
		},
		Value: argValue,
	}
}

func TestDatasFilter_Filter(t *testing.T) {
	t.Parallel()

	tt := []struct {
		name                   string
		eventID                events.ID
		fieldName              string
		parseOperatorAndValues string
		args                   []trace.Argument
		expected               bool
		expectedError          error
	}{
		{
			name:                   "Matching args value as int",
			eventID:                events.Write,
			fieldName:              "fd",
			parseOperatorAndValues: "=3",
			args: []trace.Argument{
				newArgument("fd", "int", 3),
			},
			expected: true,
		},
		{
			name:                   "Matching data value as int",
			eventID:                events.Read,
			fieldName:              "fd",
			parseOperatorAndValues: "=3",
			args: []trace.Argument{
				newArgument("fd", "int", 3),
			},
			expected: true,
		},
		{
			name:                   "Non-matching data value as int",
			eventID:                events.Read,
			fieldName:              "fd",
			parseOperatorAndValues: "=3",
			args: []trace.Argument{
				newArgument("fd", "int", 4),
			},
			expected: false,
		},
		{
			name:                   "Matching data value as string",
			eventID:                events.Open,
			fieldName:              "pathname",
			parseOperatorAndValues: "=/etc/passwd",
			args: []trace.Argument{
				newArgument("pathname", "string", "/etc/passwd"),
			},
			expected: true,
		},
		{
			name:                   "Non-matching data value as string",
			eventID:                events.Open,
			fieldName:              "pathname",
			parseOperatorAndValues: "=/etc/passwd",
			args: []trace.Argument{
				newArgument("pathname", "string", "/etc/shadow"),
			},
			expected: false,
		},
		{
			name:                   "Matching 'syscall' data value of sys_enter as string",
			eventID:                events.SysEnter,
			fieldName:              "syscall",
			parseOperatorAndValues: "=open",
			args: []trace.Argument{
				newArgument("syscall", "int", 2),
			},
			expected: true,
		},
		{
			name:                   "Matching 'syscall' data value of sys_exit as string",
			eventID:                events.SysExit,
			fieldName:              "syscall",
			parseOperatorAndValues: "=2",
			args: []trace.Argument{
				newArgument("syscall", "int", 2),
			},
			expected: true,
		},
		{
			name:                   "Non-matching 'syscall' data value of sys_enter as int",
			eventID:                events.SysExit,
			fieldName:              "syscall",
			parseOperatorAndValues: "=2",
			args: []trace.Argument{
				newArgument("syscall", "int", 1),
			},
			expected: false,
		},
		{
			name:                   "Non-matching 'syscall' data value of sys_enter as string",
			eventID:                events.SysExit,
			fieldName:              "syscall",
			parseOperatorAndValues: "=open",
			args: []trace.Argument{
				newArgument("syscall", "int", 1),
			},
			expected: false,
		},
		{
			name:                   "Matching 'syscall' data value of hooked_syscall as string",
			eventID:                events.HookedSyscall,
			fieldName:              "syscall",
			parseOperatorAndValues: "=open",
			args: []trace.Argument{
				newArgument("syscall", "string", "open"),
			},
			expected: true,
		},
		{
			name:                   "Matching 'syscall' data value of hooked_syscall as int",
			eventID:                events.HookedSyscall,
			fieldName:              "syscall",
			parseOperatorAndValues: "=2",
			args: []trace.Argument{
				newArgument("syscall", "string", "open"),
			},
			expected: true,
		},
		{
			name:                   "Non-matching 'syscall' data value of hooked_syscall as string",
			eventID:                events.HookedSyscall,
			fieldName:              "syscall",
			parseOperatorAndValues: "=open",
			args: []trace.Argument{
				newArgument("syscall", "string", "close"),
			},
			expected: false,
		},
		{
			name:                   "Non-matching 'syscall' data value of hooked_syscall as int",
			eventID:                events.HookedSyscall,
			fieldName:              "syscall",
			parseOperatorAndValues: "=2",
			args: []trace.Argument{
				newArgument("syscall", "string", "close"),
			},
			expected: false,
		},
		// Tests restrictions when a kernel data filter is available for an event.
		{
			name:                   "Invalid max length allowed for security file open event (restriction for pathname)",
			eventID:                events.SecurityFileOpen,
			fieldName:              "pathname",
			parseOperatorAndValues: "=/etc/passwd" + strings.Repeat("A", 245), // Total length 256
			args: []trace.Argument{
				newArgument("pathname", "string", "/etc/passwd"+strings.Repeat("A", 245)),
			},
			expected: false,
			expectedError: errors.New("/etc/passwdAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA exceeds max length 255"),
		},
		{
			name:                   "Valid max length allowed for event open",
			eventID:                events.Openat,
			fieldName:              "pathname",
			parseOperatorAndValues: "=/etc/passwd" + strings.Repeat("A", 245), // Total length 256
			args: []trace.Argument{
				newArgument("pathname", "string", "/etc/passwd"+strings.Repeat("A", 245)),
			},
			expected: true,
		},
		{
			name:                   "Invalid operator contains for security file open (restriction for pathname)",
			eventID:                events.SecurityFileOpen,
			fieldName:              "pathname",
			parseOperatorAndValues: "=*passwd*",
			args: []trace.Argument{
				newArgument("pathname", "string", "/etc/passwd"),
			},
			expected:      false,
			expectedError: errors.New("operator not supported for the event and data arg"),
		},
		{
			name:                   "Valid operator contains for open",
			eventID:                events.Open,
			fieldName:              "pathname",
			parseOperatorAndValues: "=*passwd*",
			args: []trace.Argument{
				newArgument("pathname", "string", "/etc/passwd"),
			},
			expected: true,
		},
	}

	for _, tc := range tt {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			filter := NewDataFilter()

			err := filter.Parse(tc.eventID, tc.fieldName, tc.parseOperatorAndValues)

			// Validate error
			if tc.expectedError != nil {
				require.Contains(t, err.Error(), tc.expectedError.Error())
			} else {
				require.NoError(t, err)
			}

			// Validate Filter
			if err == nil {
				result := filter.Filter(tc.args)
				require.Equal(t, tc.expected, result)
			}
		})
	}
}
