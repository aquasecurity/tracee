package main

import (
	"errors"
	"testing"

	"github.com/aquasecurity/tracee/tracee"
	"github.com/stretchr/testify/assert"
)

func TestPrepareFilter(t *testing.T) {

	testCases := []struct {
		testName       string
		filters        []string
		expectedFilter tracee.Filter
		expectedError  error
	}{

		{
			testName:       "invalid operator",
			filters:        []string{"uid==0"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid UID value: =0"),
		},
		{
			testName:       "invalid operator",
			filters:        []string{"uid<=0"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid UID value: =0"),
		},
		{
			testName:       "invalid operator",
			filters:        []string{"uid\t0"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid filter operator: \t"),
		},
		{
			testName:       "invalid filter type",
			filters:        []string{"UID>0"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid filter option specified, use '--filter help' for more info"),
		},
		{
			testName:       "invalid filter type",
			filters:        []string{"test=0"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid filter option specified, use '--filter help' for more info"),
		},
		{
			testName:       "invalid filter type",
			filters:        []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=0"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid filter option specified, use '--filter help' for more info"),
		},
		{
			testName:       "invalid uid",
			filters:        []string{"uid>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>0"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid UID value: >>>>>>>>>>>>>>>>>>>>>>>>>>>>>0"),
		},
		{
			testName:       "invalid uid",
			filters:        []string{"uid=a"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid UID value: a"),
		},
		{
			testName:       "invalid uid",
			filters:        []string{"uid=4294967296"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid UID value: 4294967296"),
		},
		{
			testName:       "invalid uid",
			filters:        []string{"uid=-1"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid UID value: -1"),
		},
		{
			testName:       "invalid uid",
			filters:        []string{"uid=1 1"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid UID value: 1 1"),
		},
		{
			testName:       "invalid uid",
			filters:        []string{"uid="},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid UID value: "),
		},
		{
			testName: "invalid uid",
			filters: []string{"uid=	"},
			expectedFilter: tracee.Filter{},
			expectedError: errors.New("invalid UID value: 	"),
		},
		{
			testName:       "invalid uid",
			filters:        []string{"uid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid UID value: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		},
		{
			testName:       "invalid uid",
			filters:        []string{"uid=%s"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid UID value: %s"),
		},
		{
			testName:       "invalid uid",
			filters:        []string{"uid=\t\t\t"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid UID value: \t\t\t"),
		},
		{
			testName:       "invalid uid",
			filters:        []string{"uid=0\t"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid UID value: 0\t"),
		},
		{
			testName: "uid=0",
			filters:  []string{"uid=0"},
			expectedFilter: tracee.Filter{
				UIDFilter: &tracee.UIDFilter{
					Equal:    []uint32{0},
					NotEqual: []uint32{},
					Greater:  4294967296,
					Less:     -1,
				},
			},
			expectedError: nil,
		},
		{
			testName: "uid!=0",
			filters:  []string{"uid!=0"},
			expectedFilter: tracee.Filter{
				UIDFilter: &tracee.UIDFilter{
					Equal:    []uint32{},
					NotEqual: []uint32{0},
					Greater:  -1,
					Less:     4294967296,
				},
			},
			expectedError: nil,
		},
		{
			testName: "uid>0",
			filters:  []string{"uid>0"},
			expectedFilter: tracee.Filter{
				UIDFilter: &tracee.UIDFilter{
					Equal:    []uint32{},
					NotEqual: []uint32{},
					Greater:  0,
					Less:     4294967296,
				},
			},
			expectedError: nil,
		},
		{
			testName: "uid<0",
			filters:  []string{"uid<0"},
			expectedFilter: tracee.Filter{
				UIDFilter: &tracee.UIDFilter{
					Equal:    []uint32{},
					NotEqual: []uint32{},
					Greater:  -1,
					Less:     0,
				},
			},
			expectedError: nil,
		},
	}
	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			filter, err := prepareFilter(testcase.filters)
			assert.Equal(t, testcase.expectedFilter.UIDFilter, filter.UIDFilter)
			assert.Equal(t, testcase.expectedError, err)
		})
	}
}
