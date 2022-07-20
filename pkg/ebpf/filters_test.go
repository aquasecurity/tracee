package ebpf_test

import (
	"errors"
	"testing"

	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/stretchr/testify/assert"
)

// This will only test failure cases since success cases are covered in the filter tests themselves
func TestParseProtocolFilters(t *testing.T) {
	testCases := []struct {
		testName      string
		filters       []protocol.Filter
		expectedError error
	}{
		{
			testName:      "invalid operator",
			filters:       []protocol.Filter{protocol.EqualFilter("uid", "=0")},
			expectedError: errors.New("failed to build uid filter: failed to add to filter: invalid value: =0"),
		},
		{
			testName:      "invalid operator",
			filters:       []protocol.Filter{protocol.EqualFilter("mntns", "=0")},
			expectedError: errors.New("failed to build mntns filter: failed to add to filter: invalid value: =0"),
		},
		{
			testName:      "invalid uid",
			filters:       []protocol.Filter{protocol.GreaterFilter("uid", ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>0")},
			expectedError: errors.New("failed to build uid filter: failed to add to filter: invalid value: >>>>>>>>>>>>>>>>>>>>>>>>>>>>>0"),
		},
		{
			testName:      "invalid uid",
			filters:       []protocol.Filter{protocol.EqualFilter("uid", "a")},
			expectedError: errors.New("failed to build uid filter: failed to add to filter: invalid value: a"),
		},
		{
			testName:      "invalid pidns",
			filters:       []protocol.Filter{protocol.EqualFilter("pidns", "a")},
			expectedError: errors.New("failed to build pidns filter: failed to add to filter: invalid value: a"),
		},
		{
			testName:      "invalid uid",
			filters:       []protocol.Filter{protocol.EqualFilter("uid", "4294967296")},
			expectedError: errors.New("failed to build uid filter: failed to build filter: failed to add filter: filter value 4294967296 is unsupported"),
		},
		{
			testName:      "invalid uid",
			filters:       []protocol.Filter{protocol.EqualFilter("uid", "-1")},
			expectedError: errors.New("failed to build uid filter: failed to add to filter: invalid value: -1"),
		},
		{
			testName:      "invalid mntns",
			filters:       []protocol.Filter{protocol.EqualFilter("mntns", "-1")},
			expectedError: errors.New("failed to build mntns filter: failed to add to filter: invalid value: -1"),
		},
		{
			testName:      "invalid uid",
			filters:       []protocol.Filter{protocol.EqualFilter("uid", "-1\t")},
			expectedError: errors.New("failed to build uid filter: failed to add to filter: invalid value: -1\t"),
		},
		{
			testName:      "valid pid",
			filters:       []protocol.Filter{protocol.GreaterFilter("pid", "12")},
			expectedError: nil,
		},
		{
			testName:      "invalid argfilter 1",
			filters:       []protocol.Filter{protocol.EqualFilter("open.bla", "5")},
			expectedError: errors.New("failed to build arg filter: invalid argument filter argument name: bla"),
		},
		{
			testName:      "invalid argfilter 2",
			filters:       []protocol.Filter{protocol.EqualFilter("blabla.bla", "5")},
			expectedError: errors.New("failed to build arg filter: invalid argument filter event name: blabla"),
		},
		{
			testName:      "invalid retfilter 1",
			filters:       []protocol.Filter{protocol.EqualFilter("open.retvall", "5")},
			expectedError: errors.New("failed to build arg filter: invalid argument filter argument name: retvall"),
		},
		{
			testName:      "invalid wildcard",
			filters:       []protocol.Filter{protocol.EqualFilter("event", "blah*")},
			expectedError: errors.New("invalid event to trace: blah"),
		},
		{
			testName:      "invalid wildcard 2",
			filters:       []protocol.Filter{protocol.EqualFilter("event", "bl*ah")},
			expectedError: errors.New("invalid event to trace: bl*ah"),
		},
		{
			testName:      "internal event selection",
			filters:       []protocol.Filter{protocol.EqualFilter("event", "print_syscall_table")},
			expectedError: errors.New("invalid event to trace: print_syscall_table"),
		},
		{
			testName:      "invalid not wildcard",
			filters:       []protocol.Filter{protocol.NotEqualFilter("event", "blah*")},
			expectedError: errors.New("invalid event to exclude: blah"),
		},
		{
			testName:      "invalid not wildcard 2",
			filters:       []protocol.Filter{protocol.NotEqualFilter("event", "bl*ah")},
			expectedError: errors.New("invalid event to exclude: bl*ah"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			_, err := tracee.ParseProtocolFilters(tc.filters)
			if tc.expectedError != nil {
				assert.Equal(t, tc.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
