package filters

import (
	"reflect"
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
	err := filter.Parse("read.data.fd", "=dataval", events.Core.NamesToIDs())
	require.NoError(t, err)

	copy := filter.Clone()

	opt1 := cmp.AllowUnexported(
		DataFilter{},
		StringFilter{},
		sets.PrefixSet{},
		sets.SuffixSet{},
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
	err = copy.Parse("read.data.buf", "=dataval", events.Core.NamesToIDs())
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
		parseFilterName        string
		parseOperatorAndValues string
		parseEventNamesToID    map[string]events.ID
		eventID                events.ID
		args                   []trace.Argument
		expected               bool
	}{
		// keep a single args (deprecated) filter test that shall break on future removal
		{
			name:                   "Matching args value as int",
			parseFilterName:        "write.args.fd",
			parseOperatorAndValues: "=3",
			parseEventNamesToID:    events.Core.NamesToIDs(),
			eventID:                events.Write,
			args: []trace.Argument{
				newArgument("fd", "int", 3),
			},
			expected: true,
		},
		{
			name:                   "Matching data value as int",
			parseFilterName:        "read.data.fd",
			parseOperatorAndValues: "=3",
			parseEventNamesToID:    events.Core.NamesToIDs(),
			eventID:                events.Read,
			args: []trace.Argument{
				newArgument("fd", "int", 3),
			},
			expected: true,
		},
		{
			name:                   "Non-matching data value as int",
			parseFilterName:        "read.data.fd",
			parseOperatorAndValues: "=3",
			parseEventNamesToID:    events.Core.NamesToIDs(),
			eventID:                events.Read,
			args: []trace.Argument{
				newArgument("fd", "int", 4),
			},
			expected: false,
		},
		{
			name:                   "Matching data value as string",
			parseFilterName:        "open.data.pathname",
			parseOperatorAndValues: "=/etc/passwd",
			parseEventNamesToID:    events.Core.NamesToIDs(),
			eventID:                events.Open,
			args: []trace.Argument{
				newArgument("pathname", "string", "/etc/passwd"),
			},
			expected: true,
		},
		{
			name:                   "Non-matching data value as string",
			parseFilterName:        "open.data.pathname",
			parseOperatorAndValues: "=/etc/passwd",
			parseEventNamesToID:    events.Core.NamesToIDs(),
			eventID:                events.Open,
			args: []trace.Argument{
				newArgument("pathname", "string", "/etc/shadow"),
			},
			expected: false,
		},

		// Test cases for syscall data value of sys_enter and sys_exit events
		{
			name:                   "Matching 'syscall' data value of sys_enter as string",
			parseFilterName:        "sys_enter.data.syscall",
			parseOperatorAndValues: "=open", // string value (syscall name)
			parseEventNamesToID:    events.Core.NamesToIDs(),
			eventID:                events.SysEnter,
			args: []trace.Argument{
				newArgument("syscall", "int", 2),
			},
			expected: true,
		},
		{
			name:                   "Matching 'syscall' data value of sys_exit as string",
			parseFilterName:        "sys_exit.data.syscall",
			parseOperatorAndValues: "=2", // int value (syscall id)
			parseEventNamesToID:    events.Core.NamesToIDs(),
			eventID:                events.SysExit,
			args: []trace.Argument{
				newArgument("syscall", "int", 2),
			},
			expected: true,
		},
		{
			name:                   "Non-matching 'syscall' data value of sys_enter as int",
			parseFilterName:        "sys_exit.data.syscall",
			parseOperatorAndValues: "=2", // int value (syscall number), fails to match
			parseEventNamesToID:    events.Core.NamesToIDs(),
			eventID:                events.SysExit,
			args: []trace.Argument{
				newArgument("syscall", "int", 1),
			},
			expected: false,
		},
		{
			name:                   "Non-matching 'syscall' data value of sys_enter as string",
			parseFilterName:        "sys_exit.data.syscall",
			parseOperatorAndValues: "=open", // string value (syscall name), fails to match
			parseEventNamesToID:    events.Core.NamesToIDs(),
			eventID:                events.SysExit,
			args: []trace.Argument{
				newArgument("syscall", "int", 1),
			},
			expected: false,
		},

		// Test cases for syscall data value of hooked_syscall event
		{
			name:                   "Matching 'syscall' data value of hooked_syscall as string",
			parseFilterName:        "hooked_syscall.data.syscall",
			parseOperatorAndValues: "=open", // string value (syscall name)
			parseEventNamesToID:    events.Core.NamesToIDs(),
			eventID:                events.HookedSyscall,
			args: []trace.Argument{
				newArgument("syscall", "string", "open"),
			},
			expected: true,
		},
		{
			name:                   "Matching 'syscall' data value of hooked_syscall as int",
			parseFilterName:        "hooked_syscall.data.syscall",
			parseOperatorAndValues: "=2", // int value (syscall id)
			parseEventNamesToID:    events.Core.NamesToIDs(),
			eventID:                events.HookedSyscall,
			args: []trace.Argument{
				newArgument("syscall", "string", "open"),
			},
			expected: true,
		},
		{
			name:                   "Non-matching 'syscall' data value of hooked_syscall as string",
			parseFilterName:        "hooked_syscall.data.syscall",
			parseOperatorAndValues: "=open", // string value (syscall name), fails to match
			parseEventNamesToID:    events.Core.NamesToIDs(),
			eventID:                events.HookedSyscall,
			args: []trace.Argument{
				newArgument("syscall", "string", "close"),
			},
			expected: false,
		},
		{
			name:                   "Non-matching 'syscall' data value of hooked_syscall as int",
			parseFilterName:        "hooked_syscall.data.syscall",
			parseOperatorAndValues: "=2", // int value (syscall id), fails to match
			parseEventNamesToID:    events.Core.NamesToIDs(),
			eventID:                events.HookedSyscall,
			args: []trace.Argument{
				newArgument("syscall", "string", "close"),
			},
			expected: false,
		},
	}

	for _, tc := range tt {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			filter := NewDataFilter()
			err := filter.Parse(tc.parseFilterName, tc.parseOperatorAndValues, tc.parseEventNamesToID)
			require.NoError(t, err)

			result := filter.Filter(tc.eventID, tc.args)
			require.Equal(t, tc.expected, result)
		})
	}
}
