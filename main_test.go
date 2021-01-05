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
			expectedError:  errors.New("invalid filter value: =0"),
		},
		{
			testName:       "invalid operator",
			filters:        []string{"mntns==0"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid filter value: =0"),
		},
		{
			testName:       "invalid operator",
			filters:        []string{"uid<=0"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid filter value: =0"),
		},
		{
			testName:       "invalid operator",
			filters:        []string{"uid\t0"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid filter option specified, use '--filter help' for more info"),
		},
		{
			testName:       "invalid operator",
			filters:        []string{"mntns\t0"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid filter option specified, use '--filter help' for more info"),
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
			expectedError:  errors.New("invalid filter value: >>>>>>>>>>>>>>>>>>>>>>>>>>>>>0"),
		},
		{
			testName:       "invalid uid",
			filters:        []string{"uid=a"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid filter value: a"),
		},
		{
			testName:       "invalid pidns",
			filters:        []string{"pidns=a"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid filter value: a"),
		},
		{
			testName:       "invalid uid",
			filters:        []string{"uid=4294967296"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("filter value is too big: 4294967296"),
		},
		{
			testName:       "invalid uid",
			filters:        []string{"uid=-1"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid filter value: -1"),
		},
		{
			testName:       "invalid mntns",
			filters:        []string{"mntns=-1"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid filter value: -1"),
		},
		{
			testName:       "invalid uid",
			filters:        []string{"uid=1 1"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid filter value: 1 1"),
		},
		{
			testName:       "invalid uid",
			filters:        []string{"uid="},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid operator and/or values given to filter: ="),
		},
		{
			testName:       "invalid mntns",
			filters:        []string{"mntns="},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid operator and/or values given to filter: ="),
		},
		{
			testName: "invalid uid",
			filters: []string{"uid=	"},
			expectedFilter: tracee.Filter{},
			expectedError: errors.New("invalid filter value: 	"),
		},
		{
			testName:       "invalid uid",
			filters:        []string{"uid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid filter value: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		},
		{
			testName:       "invalid uts",
			filters:        []string{"uts=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("Filtering strings of length bigger than 32 is not supported: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		},
		{
			testName:       "invalid uid",
			filters:        []string{"uid=%s"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid filter value: %s"),
		},
		{
			testName:       "invalid uid",
			filters:        []string{"uid=\t\t\t"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid filter value: \t\t\t"),
		},
		{
			testName:       "invalid uid",
			filters:        []string{"uid=0\t"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid filter value: 0\t"),
		},
		{
			testName:       "invalid pidns",
			filters:        []string{"pidns=0\t"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid filter value: 0\t"),
		},
		{
			testName: "uid=0",
			filters:  []string{"uid=0"},
			expectedFilter: tracee.Filter{
				UIDFilter: &tracee.UintFilter{
					Equal:    []uint64{0},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  true,
					Enabled:  true,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  true,
					Enabled:  false,
				},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  false,
					Enabled:  false,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  false,
					Enabled:  false,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Enabled:  false,
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Enabled:  false,
				},
				ContFilter: &tracee.BoolFilter{
					Value:   false,
					Enabled: false,
				},
			},
			expectedError: nil,
		},
		{
			testName: "uid!=0",
			filters:  []string{"uid!=0"},
			expectedFilter: tracee.Filter{
				UIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{0},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  true,
					Enabled:  true,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  true,
					Enabled:  false,
				},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  false,
					Enabled:  false,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  false,
					Enabled:  false,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Enabled:  false,
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Enabled:  false,
				},
				ContFilter: &tracee.BoolFilter{
					Value:   false,
					Enabled: false,
				},
			},
			expectedError: nil,
		},
		{
			testName: "mntns=0",
			filters:  []string{"mntns=0"},
			expectedFilter: tracee.Filter{
				UIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  true,
					Enabled:  false,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  true,
					Enabled:  false,
				},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{0},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  false,
					Enabled:  true,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  false,
					Enabled:  false,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Enabled:  false,
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Enabled:  false,
				},
				ContFilter: &tracee.BoolFilter{
					Value:   false,
					Enabled: false,
				},
			},
			expectedError: nil,
		},
		{
			testName: "pidns!=0",
			filters:  []string{"pidns!=0"},
			expectedFilter: tracee.Filter{
				UIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  true,
					Enabled:  false,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  true,
					Enabled:  false,
				},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  false,
					Enabled:  false,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{0},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  false,
					Enabled:  true,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Enabled:  false,
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Enabled:  false,
				},
				ContFilter: &tracee.BoolFilter{
					Value:   false,
					Enabled: false,
				},
			},
			expectedError: nil,
		},
		{
			testName: "comm=ls",
			filters:  []string{"comm=ls"},
			expectedFilter: tracee.Filter{
				UIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  true,
					Enabled:  false,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  true,
					Enabled:  false,
				},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  false,
					Enabled:  false,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  false,
					Enabled:  false,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{"ls"},
					NotEqual: []string{},
					Enabled:  true,
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Enabled:  false,
				},
				ContFilter: &tracee.BoolFilter{
					Value:   false,
					Enabled: false,
				},
			},
			expectedError: nil,
		},
		{
			testName: "uts!=deadbeaf",
			filters:  []string{"uts!=deadbeaf"},
			expectedFilter: tracee.Filter{
				UIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  true,
					Enabled:  false,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  true,
					Enabled:  false,
				},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  false,
					Enabled:  false,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  false,
					Enabled:  false,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Enabled:  false,
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{"deadbeaf"},
					Enabled:  true,
				},
				ContFilter: &tracee.BoolFilter{
					Value:   false,
					Enabled: false,
				},
			},
			expectedError: nil,
		},
		{
			testName: "uid>0",
			filters:  []string{"uid>0"},
			expectedFilter: tracee.Filter{
				UIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  0,
					Is32Bit:  true,
					Enabled:  true,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  true,
					Enabled:  false,
				},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  false,
					Enabled:  false,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  false,
					Enabled:  false,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Enabled:  false,
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Enabled:  false,
				},
				ContFilter: &tracee.BoolFilter{
					Value:   false,
					Enabled: false,
				},
			},
			expectedError: nil,
		},
		{
			testName: "uid<0",
			filters:  []string{"uid<0"},
			expectedFilter: tracee.Filter{
				UIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     0,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  true,
					Enabled:  true,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  true,
					Enabled:  false,
				},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  false,
					Enabled:  false,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  false,
					Enabled:  false,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Enabled:  false,
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Enabled:  false,
				},
				ContFilter: &tracee.BoolFilter{
					Value:   false,
					Enabled: false,
				},
			},
			expectedError: nil,
		},
		{
			testName: "container",
			filters:  []string{"container"},
			expectedFilter: tracee.Filter{
				UIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  true,
					Enabled:  false,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  true,
					Enabled:  false,
				},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  false,
					Enabled:  false,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  false,
					Enabled:  false,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Enabled:  false,
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Enabled:  false,
				},
				ContFilter: &tracee.BoolFilter{
					Value:   true,
					Enabled: true,
				},
			},
			expectedError: nil,
		},
		{
			testName: "multiple filters",
			filters:  []string{"uid<1", "mntns=5", "pidns!=3", "pid!=10", "comm=ps", "uts!=abc", "!c"},
			expectedFilter: tracee.Filter{
				UIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     1,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  true,
					Enabled:  true,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{10},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  true,
					Enabled:  true,
				},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{5},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  false,
					Enabled:  true,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{3},
					Less:     tracee.LessNotSet,
					Greater:  tracee.GreaterNotSet,
					Is32Bit:  false,
					Enabled:  true,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{"ps"},
					NotEqual: []string{},
					Enabled:  true,
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{"abc"},
					Enabled:  true,
				},
				ContFilter: &tracee.BoolFilter{
					Value:   false,
					Enabled: true,
				},
			},
			expectedError: nil,
		},
	}
	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			filter, err := prepareFilter(testcase.filters)
			assert.Equal(t, testcase.expectedFilter.UIDFilter, filter.UIDFilter)
			assert.Equal(t, testcase.expectedFilter.PIDFilter, filter.PIDFilter)
			assert.Equal(t, testcase.expectedFilter.MntNSFilter, filter.MntNSFilter)
			assert.Equal(t, testcase.expectedFilter.PidNSFilter, filter.PidNSFilter)
			assert.Equal(t, testcase.expectedFilter.UTSFilter, filter.UTSFilter)
			assert.Equal(t, testcase.expectedFilter.CommFilter, filter.CommFilter)
			assert.Equal(t, testcase.expectedFilter.ContFilter, filter.ContFilter)
			assert.Equal(t, testcase.expectedError, err)
		})
	}
}
