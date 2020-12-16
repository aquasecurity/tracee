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
			filters:        []string{"mntns==0"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid NS value: =0"),
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
			testName:       "invalid operator",
			filters:        []string{"mntns\t0"},
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
			testName:       "invalid pidns",
			filters:        []string{"pidns=a"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid NS value: a"),
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
			testName:       "invalid mntns",
			filters:        []string{"mntns=-1"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid NS value: -1"),
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
			testName:       "invalid mntns",
			filters:        []string{"mntns="},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid NS value: "),
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
			testName:       "invalid uts",
			filters:        []string{"uts=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("Filtering strings of length bigger than 16 is not supported: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
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
			testName:       "invalid pidns",
			filters:        []string{"pidns=0\t"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid NS value: 0\t"),
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
					Enabled:  true,
				},
				MntNSFilter: &tracee.NSFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					FilterIn: false,
					Enabled:  false,
				},
				PidNSFilter: &tracee.NSFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					FilterIn: false,
					Enabled:  false,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					FilterIn: false,
					Enabled:  false,
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					FilterIn: false,
					Enabled:  false,
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
					Enabled:  true,
				},
				MntNSFilter: &tracee.NSFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					FilterIn: false,
					Enabled:  false,
				},
				PidNSFilter: &tracee.NSFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					FilterIn: false,
					Enabled:  false,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					FilterIn: false,
					Enabled:  false,
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					FilterIn: false,
					Enabled:  false,
				},
			},
			expectedError: nil,
		},
		{
			testName: "mntns=0",
			filters:  []string{"mntns=0"},
			expectedFilter: tracee.Filter{
				UIDFilter: &tracee.UIDFilter{
					Equal:    []uint32{},
					NotEqual: []uint32{},
					Greater:  -1,
					Less:     4294967296,
					Enabled:  false,
				},
				MntNSFilter: &tracee.NSFilter{
					Equal:    []uint64{0},
					NotEqual: []uint64{},
					FilterIn: true,
					Enabled:  true,
				},
				PidNSFilter: &tracee.NSFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					FilterIn: false,
					Enabled:  false,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					FilterIn: false,
					Enabled:  false,
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					FilterIn: false,
					Enabled:  false,
				},
			},
			expectedError: nil,
		},
		{
			testName: "pidns!=0",
			filters:  []string{"pidns!=0"},
			expectedFilter: tracee.Filter{
				UIDFilter: &tracee.UIDFilter{
					Equal:    []uint32{},
					NotEqual: []uint32{},
					Greater:  -1,
					Less:     4294967296,
					Enabled:  false,
				},
				MntNSFilter: &tracee.NSFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					FilterIn: false,
					Enabled:  false,
				},
				PidNSFilter: &tracee.NSFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{0},
					FilterIn: false,
					Enabled:  true,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					FilterIn: false,
					Enabled:  false,
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					FilterIn: false,
					Enabled:  false,
				},
			},
			expectedError: nil,
		},
		{
			testName: "comm=ls",
			filters:  []string{"comm=ls"},
			expectedFilter: tracee.Filter{
				UIDFilter: &tracee.UIDFilter{
					Equal:    []uint32{},
					NotEqual: []uint32{},
					Greater:  -1,
					Less:     4294967296,
					Enabled:  false,
				},
				MntNSFilter: &tracee.NSFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					FilterIn: false,
					Enabled:  false,
				},
				PidNSFilter: &tracee.NSFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					FilterIn: false,
					Enabled:  false,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{"ls"},
					NotEqual: []string{},
					FilterIn: true,
					Enabled:  true,
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					FilterIn: false,
					Enabled:  false,
				},
			},
			expectedError: nil,
		},
		{
			testName: "uts!=deadbeaf",
			filters:  []string{"uts!=deadbeaf"},
			expectedFilter: tracee.Filter{
				UIDFilter: &tracee.UIDFilter{
					Equal:    []uint32{},
					NotEqual: []uint32{},
					Greater:  -1,
					Less:     4294967296,
					Enabled:  false,
				},
				MntNSFilter: &tracee.NSFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					FilterIn: false,
					Enabled:  false,
				},
				PidNSFilter: &tracee.NSFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					FilterIn: false,
					Enabled:  false,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					FilterIn: false,
					Enabled:  false,
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{"deadbeaf"},
					FilterIn: false,
					Enabled:  true,
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
					Enabled:  true,
				},
				MntNSFilter: &tracee.NSFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					FilterIn: false,
					Enabled:  false,
				},
				PidNSFilter: &tracee.NSFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					FilterIn: false,
					Enabled:  false,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					FilterIn: false,
					Enabled:  false,
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					FilterIn: false,
					Enabled:  false,
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
					Enabled:  true,
				},
				MntNSFilter: &tracee.NSFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					FilterIn: false,
					Enabled:  false,
				},
				PidNSFilter: &tracee.NSFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					FilterIn: false,
					Enabled:  false,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					FilterIn: false,
					Enabled:  false,
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					FilterIn: false,
					Enabled:  false,
				},
			},
			expectedError: nil,
		},
		{
			testName: "multiple filters",
			filters:  []string{"uid<0", "mntns=5", "pidns!=3", "comm=ps", "uts!=abc"},
			expectedFilter: tracee.Filter{
				UIDFilter: &tracee.UIDFilter{
					Equal:    []uint32{},
					NotEqual: []uint32{},
					Greater:  -1,
					Less:     0,
					Enabled:  true,
				},
				MntNSFilter: &tracee.NSFilter{
					Equal:    []uint64{5},
					NotEqual: []uint64{},
					FilterIn: true,
					Enabled:  true,
				},
				PidNSFilter: &tracee.NSFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{3},
					FilterIn: false,
					Enabled:  true,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{"ps"},
					NotEqual: []string{},
					FilterIn: true,
					Enabled:  true,
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{"abc"},
					FilterIn: false,
					Enabled:  true,
				},
			},
			expectedError: nil,
		},
	}
	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			filter, err := prepareFilter(testcase.filters)
			assert.Equal(t, testcase.expectedFilter.UIDFilter, filter.UIDFilter)
			assert.Equal(t, testcase.expectedFilter.MntNSFilter, filter.MntNSFilter)
			assert.Equal(t, testcase.expectedFilter.PidNSFilter, filter.PidNSFilter)
			assert.Equal(t, testcase.expectedFilter.UTSFilter, filter.UTSFilter)
			assert.Equal(t, testcase.expectedFilter.CommFilter, filter.CommFilter)
			assert.Equal(t, testcase.expectedError, err)
		})
	}
}
