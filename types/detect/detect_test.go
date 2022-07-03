package detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilter_FlattenIfaceSlice(t *testing.T) {
	testSlice := []interface{}{[]string{"a", "b", "c"}, []int{1, 2, 3}, "bruh"}
	expected := []interface{}{"a", "b", "c", 1, 2, 3, "bruh"}
	assert.Equal(t, expected, flattenIfaceArr(testSlice))
}

func TestFilter_String(t *testing.T) {
	testCases := []struct {
		name     string
		filter   Filter
		expected string
	}{
		{
			name:     "equal filter 1",
			filter:   EqualFilter("event", "security_file_open", "execve"),
			expected: "event=security_file_open,execve",
		},
		{
			name:     "equal filter 2 - numeric",
			filter:   EqualFilter("security_socket_connect.args.syscall", 101, 21),
			expected: "security_socket_connect.args.syscall=101,21",
		},
		{
			name:     "greater filter",
			filter:   GreaterFilter("num", 2),
			expected: "num>2",
		},
		{
			name:     "lesser filter",
			filter:   LowerFilter("num", 2, -1, 5),
			expected: "num<2,-1,5",
		},
		{
			name:     "prefix filter",
			filter:   PrefixFilter("arg", "hi", "bye"),
			expected: "arg=hi*,bye*",
		},
		{
			name:     "suffix filter",
			filter:   SuffixFilter("arg", "hi", "bye"),
			expected: "arg=*hi,*bye",
		},
		{
			name:     "contains filter",
			filter:   ContainsFilter("arg", "hi", "bye"),
			expected: "arg=*hi*,*bye*",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.filter.String())
		})
	}
}
