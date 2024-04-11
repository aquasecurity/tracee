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

func TestArgsFilterClone(t *testing.T) {
	t.Parallel()

	filter := NewArgFilter()
	err := filter.Parse("read.args.fd", "=argval", events.Core.NamesToIDs())
	require.NoError(t, err)

	copy := filter.Clone()

	opt1 := cmp.AllowUnexported(
		ArgFilter{},
		StringFilter{},
		sets.PrefixSet{},
		sets.SuffixSet{},
	)
	opt2 := cmp.FilterPath(func(p cmp.Path) bool {
		// ignore the valueHandler function
		// https://cs.opensource.google/go/go/+/refs/tags/go1.22.0:src/reflect/deepequal.go;l=187
		return p.Last().String() == ".valueHandler"
	}, cmp.Ignore())

	if !cmp.Equal(filter, copy, opt1, opt2) {
		t.Errorf("Clone did not produce an identical copy")
	}

	// ensure that changes to the copy do not affect the original
	err = copy.Parse("read.args.buf", "=argval", events.Core.NamesToIDs())
	require.NoError(t, err)
	if reflect.DeepEqual(filter, copy) {
		t.Errorf("Changes to copied filter affected the original")
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

func TestArgsFilter_Filter(t *testing.T) {
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
		{
			name:                   "Matching argument value as int",
			parseFilterName:        "read.args.fd",
			parseOperatorAndValues: "=3",
			parseEventNamesToID:    events.Core.NamesToIDs(),
			eventID:                events.Read,
			args: []trace.Argument{
				newArgument("fd", "int", 3),
			},
			expected: true,
		},
		{
			name:                   "Non-matching argument value as int",
			parseFilterName:        "read.args.fd",
			parseOperatorAndValues: "=3",
			parseEventNamesToID:    events.Core.NamesToIDs(),
			eventID:                events.Read,
			args: []trace.Argument{
				newArgument("fd", "int", 4),
			},
			expected: false,
		},
		{
			name:                   "Matching argument value as string",
			parseFilterName:        "open.args.pathname",
			parseOperatorAndValues: "=/etc/passwd",
			parseEventNamesToID:    events.Core.NamesToIDs(),
			eventID:                events.Open,
			args: []trace.Argument{
				newArgument("pathname", "string", "/etc/passwd"),
			},
			expected: true,
		},
		{
			name:                   "Non-matching argument value as string",
			parseFilterName:        "open.args.pathname",
			parseOperatorAndValues: "=/etc/passwd",
			parseEventNamesToID:    events.Core.NamesToIDs(),
			eventID:                events.Open,
			args: []trace.Argument{
				newArgument("pathname", "string", "/etc/shadow"),
			},
			expected: false,
		},

		// Test cases for syscall argument value of sys_enter and sys_exit events
		{
			name:                   "Matching 'syscall' argument value of sys_enter as string",
			parseFilterName:        "sys_enter.args.syscall",
			parseOperatorAndValues: "=open", // string value (syscall name)
			parseEventNamesToID:    events.Core.NamesToIDs(),
			eventID:                events.SysEnter,
			args: []trace.Argument{
				newArgument("syscall", "int", 2),
			},
			expected: true,
		},
		{
			name:                   "Matching 'syscall' argument value of sys_exit as string",
			parseFilterName:        "sys_exit.args.syscall",
			parseOperatorAndValues: "=2", // int value (syscall id)
			parseEventNamesToID:    events.Core.NamesToIDs(),
			eventID:                events.SysExit,
			args: []trace.Argument{
				newArgument("syscall", "int", 2),
			},
			expected: true,
		},
		{
			name:                   "Non-matching 'syscall' argument value of sys_enter as int",
			parseFilterName:        "sys_exit.args.syscall",
			parseOperatorAndValues: "=2", // int value (syscall number), fails to match
			parseEventNamesToID:    events.Core.NamesToIDs(),
			eventID:                events.SysExit,
			args: []trace.Argument{
				newArgument("syscall", "int", 1),
			},
			expected: false,
		},
		{
			name:                   "Non-matching 'syscall' argument value of sys_enter as string",
			parseFilterName:        "sys_exit.args.syscall",
			parseOperatorAndValues: "=open", // string value (syscall name), fails to match
			parseEventNamesToID:    events.Core.NamesToIDs(),
			eventID:                events.SysExit,
			args: []trace.Argument{
				newArgument("syscall", "int", 1),
			},
			expected: false,
		},

		// Test cases for syscall argument value of hooked_syscall event
		{
			name:                   "Matching 'syscall' argument value of hooked_syscall as string",
			parseFilterName:        "hooked_syscall.args.syscall",
			parseOperatorAndValues: "=open", // string value (syscall name)
			parseEventNamesToID:    events.Core.NamesToIDs(),
			eventID:                events.HookedSyscall,
			args: []trace.Argument{
				newArgument("syscall", "string", "open"),
			},
			expected: true,
		},
		{
			name:                   "Matching 'syscall' argument value of hooked_syscall as int",
			parseFilterName:        "hooked_syscall.args.syscall",
			parseOperatorAndValues: "=2", // int value (syscall id)
			parseEventNamesToID:    events.Core.NamesToIDs(),
			eventID:                events.HookedSyscall,
			args: []trace.Argument{
				newArgument("syscall", "string", "open"),
			},
			expected: true,
		},
		{
			name:                   "Non-matching 'syscall' argument value of hooked_syscall as string",
			parseFilterName:        "hooked_syscall.args.syscall",
			parseOperatorAndValues: "=open", // string value (syscall name), fails to match
			parseEventNamesToID:    events.Core.NamesToIDs(),
			eventID:                events.HookedSyscall,
			args: []trace.Argument{
				newArgument("syscall", "string", "close"),
			},
			expected: false,
		},
		{
			name:                   "Non-matching 'syscall' argument value of hooked_syscall as int",
			parseFilterName:        "hooked_syscall.args.syscall",
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

			filter := NewArgFilter()
			err := filter.Parse(tc.parseFilterName, tc.parseOperatorAndValues, tc.parseEventNamesToID)
			require.NoError(t, err)

			result := filter.Filter(tc.eventID, tc.args)
			require.Equal(t, tc.expected, result)
		})
	}
}
