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
			testName:       "invalid argfilter 1",
			filters:        []string{"open."},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid argument filter argument name: "),
		},
		{
			testName:       "invalid argfilter 2",
			filters:        []string{"blabla.bla"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid argument filter event name: blabla"),
		},
		{
			testName:       "invalid argfilter 3",
			filters:        []string{"blabla.bla=5"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid argument filter event name: blabla"),
		},
		{
			testName:       "invalid argfilter 4",
			filters:        []string{"open.bla=5"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid argument filter argument name: bla"),
		},
		{
			testName:       "invalid retfilter 1",
			filters:        []string{".retval"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid retval filter event name: "),
		},
		{
			testName:       "invalid retfilter 2",
			filters:        []string{"open.retvall"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid retval filter format open.retvall"),
		},
		{
			testName: "uid=0",
			filters:  []string{"uid=0"},
			expectedFilter: tracee.Filter{
				UIDFilter: &tracee.UintFilter{
					Equal:    []uint64{0},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
					Enabled:  true,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
				},
				NewPidFilter: &tracee.BoolFilter{},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
				},
				ContFilter:    &tracee.BoolFilter{},
				NewContFilter: &tracee.BoolFilter{},
				ArgFilter: &tracee.ArgFilter{
					Filters: map[int32]map[string]tracee.ArgFilterVal{},
				},
				RetFilter: &tracee.RetFilter{
					Filters: map[int32]tracee.IntFilter{},
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
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
					Enabled:  true,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
				},
				NewPidFilter: &tracee.BoolFilter{},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
				},
				ContFilter:    &tracee.BoolFilter{},
				NewContFilter: &tracee.BoolFilter{},
				ArgFilter: &tracee.ArgFilter{
					Filters: map[int32]map[string]tracee.ArgFilterVal{},
				},
				RetFilter: &tracee.RetFilter{
					Filters: map[int32]tracee.IntFilter{},
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
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
				},
				NewPidFilter: &tracee.BoolFilter{},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{0},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Enabled:  true,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
				},
				ContFilter:    &tracee.BoolFilter{},
				NewContFilter: &tracee.BoolFilter{},
				ArgFilter: &tracee.ArgFilter{
					Filters: map[int32]map[string]tracee.ArgFilterVal{},
				},
				RetFilter: &tracee.RetFilter{
					Filters: map[int32]tracee.IntFilter{},
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
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
				},
				NewPidFilter: &tracee.BoolFilter{},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{0},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Enabled:  true,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
				},
				ContFilter:    &tracee.BoolFilter{},
				NewContFilter: &tracee.BoolFilter{},
				ArgFilter: &tracee.ArgFilter{
					Filters: map[int32]map[string]tracee.ArgFilterVal{},
				},
				RetFilter: &tracee.RetFilter{
					Filters: map[int32]tracee.IntFilter{},
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
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
				},
				NewPidFilter: &tracee.BoolFilter{},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{"ls"},
					NotEqual: []string{},
					Enabled:  true,
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
				},
				ContFilter:    &tracee.BoolFilter{},
				NewContFilter: &tracee.BoolFilter{},
				ArgFilter: &tracee.ArgFilter{
					Filters: map[int32]map[string]tracee.ArgFilterVal{},
				},
				RetFilter: &tracee.RetFilter{
					Filters: map[int32]tracee.IntFilter{},
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
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
				},
				NewPidFilter: &tracee.BoolFilter{},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{"deadbeaf"},
					Enabled:  true,
				},
				ContFilter:    &tracee.BoolFilter{},
				NewContFilter: &tracee.BoolFilter{},
				ArgFilter: &tracee.ArgFilter{
					Filters: map[int32]map[string]tracee.ArgFilterVal{},
				},
				RetFilter: &tracee.RetFilter{
					Filters: map[int32]tracee.IntFilter{},
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
					Less:     tracee.LessNotSetUint,
					Greater:  0,
					Is32Bit:  true,
					Enabled:  true,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
				},
				NewPidFilter: &tracee.BoolFilter{},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
				},
				ContFilter:    &tracee.BoolFilter{},
				NewContFilter: &tracee.BoolFilter{},
				ArgFilter: &tracee.ArgFilter{
					Filters: map[int32]map[string]tracee.ArgFilterVal{},
				},
				RetFilter: &tracee.RetFilter{
					Filters: map[int32]tracee.IntFilter{},
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
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
					Enabled:  true,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
				},
				NewPidFilter: &tracee.BoolFilter{},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
				},
				ContFilter:    &tracee.BoolFilter{},
				NewContFilter: &tracee.BoolFilter{},
				ArgFilter: &tracee.ArgFilter{
					Filters: map[int32]map[string]tracee.ArgFilterVal{},
				},
				RetFilter: &tracee.RetFilter{
					Filters: map[int32]tracee.IntFilter{},
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
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
				},
				NewPidFilter: &tracee.BoolFilter{
					Value:   true,
					Enabled: true,
				},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
				},
				ContFilter: &tracee.BoolFilter{
					Value:   true,
					Enabled: true,
				},
				NewContFilter: &tracee.BoolFilter{},
				ArgFilter: &tracee.ArgFilter{
					Filters: map[int32]map[string]tracee.ArgFilterVal{},
				},
				RetFilter: &tracee.RetFilter{
					Filters: map[int32]tracee.IntFilter{},
				},
			},
			expectedError: nil,
		},
		{
			testName: "container=new",
			filters:  []string{"container=new"},
			expectedFilter: tracee.Filter{
				UIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
				},
				NewPidFilter: &tracee.BoolFilter{
					Value:   true,
					Enabled: true,
				},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
				},
				ContFilter: &tracee.BoolFilter{},
				NewContFilter: &tracee.BoolFilter{
					Value:   true,
					Enabled: true,
				},
				ArgFilter: &tracee.ArgFilter{
					Filters: map[int32]map[string]tracee.ArgFilterVal{},
				},
				RetFilter: &tracee.RetFilter{
					Filters: map[int32]tracee.IntFilter{},
				},
			},
			expectedError: nil,
		},
		{
			testName: "argfilter",
			filters:  []string{"openat.pathname=/bin/ls,/tmp/tracee", "openat.pathname!=/etc/passwd"},
			expectedFilter: tracee.Filter{
				UIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
				},
				NewPidFilter: &tracee.BoolFilter{},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
				},
				ContFilter:    &tracee.BoolFilter{},
				NewContFilter: &tracee.BoolFilter{},
				ArgFilter: &tracee.ArgFilter{
					Filters: map[int32]map[string]tracee.ArgFilterVal{
						257: {
							"pathname": tracee.ArgFilterVal{
								Equal:    []string{"/bin/ls", "/tmp/tracee"},
								NotEqual: []string{"/etc/passwd"},
							},
						},
					},
					Enabled: true,
				},
				RetFilter: &tracee.RetFilter{
					Filters: map[int32]tracee.IntFilter{},
				},
			},
			expectedError: nil,
		},
		{
			testName: "retfilter",
			filters:  []string{"openat.retval=2", "openat.retval>1"},
			expectedFilter: tracee.Filter{
				UIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
				},
				NewPidFilter: &tracee.BoolFilter{},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
				},
				CommFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
				},
				UTSFilter: &tracee.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
				},
				ContFilter:    &tracee.BoolFilter{},
				NewContFilter: &tracee.BoolFilter{},
				ArgFilter: &tracee.ArgFilter{
					Filters: map[int32]map[string]tracee.ArgFilterVal{},
				},
				RetFilter: &tracee.RetFilter{
					Filters: map[int32]tracee.IntFilter{
						257: {
							Equal:    []int64{2},
							NotEqual: []int64{},
							Less:     tracee.LessNotSetInt,
							Greater:  1,
							Enabled:  true,
						},
					},
					Enabled: true,
				},
			},
			expectedError: nil,
		},
		{
			testName: "multiple filters",
			filters:  []string{"uid<1", "mntns=5", "pidns!=3", "pid!=10", "comm=ps", "uts!=abc"},
			expectedFilter: tracee.Filter{
				UIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     1,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
					Enabled:  true,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{10},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
					Enabled:  true,
				},
				NewPidFilter: &tracee.BoolFilter{},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{5},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Enabled:  true,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{3},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
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
				ContFilter:    &tracee.BoolFilter{},
				NewContFilter: &tracee.BoolFilter{},
				ArgFilter: &tracee.ArgFilter{
					Filters: map[int32]map[string]tracee.ArgFilterVal{},
				},
				RetFilter: &tracee.RetFilter{
					Filters: map[int32]tracee.IntFilter{},
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
			assert.Equal(t, testcase.expectedFilter.NewPidFilter, filter.NewPidFilter)
			assert.Equal(t, testcase.expectedFilter.MntNSFilter, filter.MntNSFilter)
			assert.Equal(t, testcase.expectedFilter.PidNSFilter, filter.PidNSFilter)
			assert.Equal(t, testcase.expectedFilter.UTSFilter, filter.UTSFilter)
			assert.Equal(t, testcase.expectedFilter.CommFilter, filter.CommFilter)
			assert.Equal(t, testcase.expectedFilter.ContFilter, filter.ContFilter)
			assert.Equal(t, testcase.expectedFilter.NewContFilter, filter.NewContFilter)
			assert.Equal(t, testcase.expectedFilter.ArgFilter, filter.ArgFilter)
			assert.Equal(t, testcase.expectedFilter.RetFilter, filter.RetFilter)
			assert.Equal(t, testcase.expectedError, err)
		})
	}
}

func TestPrepareCapture(t *testing.T) {

	testCases := []struct {
		testName        string
		captureSlice    []string
		expectedCapture tracee.CaptureConfig
		expectedError   error
	}{
		{
			testName:        "invalid capture option",
			captureSlice:    []string{"foo"},
			expectedCapture: tracee.CaptureConfig{},
			expectedError:   errors.New("invalid capture option specified, use '--capture help' for more info"),
		},
		{
			testName:        "invalid capture write filter",
			captureSlice:    []string{"write="},
			expectedCapture: tracee.CaptureConfig{},
			expectedError:   errors.New("invalid capture option specified, use '--capture help' for more info"),
		},
		{
			testName:        "invalid capture write filter 2",
			captureSlice:    []string{"write=/tmp"},
			expectedCapture: tracee.CaptureConfig{},
			expectedError:   errors.New("invalid capture option specified, use '--capture help' for more info"),
		},
		{
			testName:        "empty capture write filter",
			captureSlice:    []string{"write=*"},
			expectedCapture: tracee.CaptureConfig{},
			expectedError:   errors.New("capture write filter cannot be empty"),
		},
		{
			testName:     "capture mem",
			captureSlice: []string{"mem"},
			expectedCapture: tracee.CaptureConfig{
				OutputPath: "/tmp/tracee/out",
				Mem:        true,
			},
			expectedError: nil,
		},
		{
			testName:     "capture exec",
			captureSlice: []string{"exec"},
			expectedCapture: tracee.CaptureConfig{
				OutputPath: "/tmp/tracee/out",
				Exec:       true,
			},
			expectedError: nil,
		},
		{
			testName:     "capture write",
			captureSlice: []string{"write"},
			expectedCapture: tracee.CaptureConfig{
				OutputPath: "/tmp/tracee/out",
				FileWrite:  true,
			},
			expectedError: nil,
		},
		{
			testName:     "capture write filtered",
			captureSlice: []string{"write=/tmp*"},
			expectedCapture: tracee.CaptureConfig{
				OutputPath:      "/tmp/tracee/out",
				FileWrite:       true,
				FilterFileWrite: []string{"/tmp"},
			},
			expectedError: nil,
		},
		{
			testName:     "capture all",
			captureSlice: []string{"all"},
			expectedCapture: tracee.CaptureConfig{
				OutputPath: "/tmp/tracee/out",
				FileWrite:  true,
				Mem:        true,
				Exec:       true,
			},
			expectedError: nil,
		},
		{
			testName:     "multiple capture options",
			captureSlice: []string{"write", "exec", "mem"},
			expectedCapture: tracee.CaptureConfig{
				OutputPath: "/tmp/tracee/out",
				FileWrite:  true,
				Mem:        true,
				Exec:       true,
			},
			expectedError: nil,
		},
	}
	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			capture, err := prepareCapture(testcase.captureSlice)
			assert.Equal(t, testcase.expectedCapture.FileWrite, capture.FileWrite)
			assert.Equal(t, testcase.expectedCapture.FilterFileWrite, capture.FilterFileWrite)
			assert.Equal(t, testcase.expectedCapture.Exec, capture.Exec)
			assert.Equal(t, testcase.expectedCapture.Mem, capture.Mem)
			assert.Equal(t, testcase.expectedCapture.OutputPath, capture.OutputPath)
			assert.Equal(t, testcase.expectedError, err)
		})
	}
}

func TestPrepareOutput(t *testing.T) {

	testCases := []struct {
		testName       string
		outputSlice    []string
		expectedOutput tracee.OutputConfig
		expectedError  error
	}{
		{
			testName:    "invalid output option",
			outputSlice: []string{"foo"},
			// it's not the preparer job to validate input. in this case foo is considered an implicit output format.
			expectedOutput: tracee.OutputConfig{
				Format: "foo",
			},
			expectedError: nil,
		},
		{
			testName:       "invalid output option",
			outputSlice:    []string{"option:"},
			expectedOutput: tracee.OutputConfig{},
			expectedError:  errors.New("invalid output option: , use '--option help' for more info"),
		},
		{
			testName:       "invalid output option 2",
			outputSlice:    []string{"option:foo"},
			expectedOutput: tracee.OutputConfig{},
			expectedError:  errors.New("invalid output option: foo, use '--option help' for more info"),
		},
		{
			testName:    "format explicit",
			outputSlice: []string{"format:json"},
			expectedOutput: tracee.OutputConfig{
				Format: "json",
			},
			expectedError: nil,
		},
		{
			testName:    "format implicit",
			outputSlice: []string{"json"},
			expectedOutput: tracee.OutputConfig{
				Format: "json",
			},
			expectedError: nil,
		},
		{
			testName:    "format gotemplate",
			outputSlice: []string{"gotemplate=/path/to/tmpl"},
			expectedOutput: tracee.OutputConfig{
				Format: "gotemplate=/path/to/tmpl",
			},
			expectedError: nil,
		},
		{
			testName:    "out",
			outputSlice: []string{"out-file:/path/to/file"},
			expectedOutput: tracee.OutputConfig{
				OutPath: "/path/to/file",
				Format:  "table",
			},
			expectedError: nil,
		},
		{
			testName:    "empty val",
			outputSlice: []string{"out-file"},
			expectedOutput: tracee.OutputConfig{
				Format: "out-file",
			},
			expectedError: nil,
		},
		{
			testName:    "err",
			outputSlice: []string{"err-file:/path/to/file"},
			expectedOutput: tracee.OutputConfig{
				ErrPath: "/path/to/file",
				Format:  "table",
			},
			expectedError: nil,
		},
		{
			testName:    "option eot",
			outputSlice: []string{"option:eot"},
			expectedOutput: tracee.OutputConfig{
				EOT:    true,
				Format: "table",
			},
			expectedError: nil,
		},
		{
			testName:    "option stack-addresses",
			outputSlice: []string{"option:stack-addresses"},
			expectedOutput: tracee.OutputConfig{
				StackAddresses: true,
				Format:         "table",
			},
			expectedError: nil,
		},
		{
			testName:    "option detect-syscall",
			outputSlice: []string{"option:detect-syscall"},
			expectedOutput: tracee.OutputConfig{
				DetectSyscall: true,
				Format:        "table",
			},
			expectedError: nil,
		},
		{
			testName:    "option exec-env",
			outputSlice: []string{"option:exec-env"},
			expectedOutput: tracee.OutputConfig{
				ExecEnv: true,
				Format:  "table",
			},
			expectedError: nil,
		},
		{
			testName:    "gob + eot",
			outputSlice: []string{"format:gob", "option:eot"},
			expectedOutput: tracee.OutputConfig{
				Format: "gob",
				EOT:    true,
			},
			expectedError: nil,
		},
		{
			testName:    "all",
			outputSlice: []string{"gotemplate=/path/to/tmpl", "option:eot", "option:stack-addresses", "option:detect-syscall", "option:exec-env", "out-file:/path/to/file", "err-file:/path/to/file"},
			expectedOutput: tracee.OutputConfig{
				Format:         "gotemplate=/path/to/tmpl",
				OutPath:        "/path/to/file",
				ErrPath:        "/path/to/file",
				EOT:            true,
				StackAddresses: true,
				DetectSyscall:  true,
				ExecEnv:        true,
			},
			expectedError: nil,
		},
	}
	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			output, err := prepareOutput(testcase.outputSlice)
			if err != nil {
				assert.Equal(t, testcase.expectedError, err)
			} else {
				assert.Equal(t, testcase.expectedOutput, output)
			}
		})
	}
}
