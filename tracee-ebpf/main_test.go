package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/syndtr/gocapability/capability"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/tracee-ebpf/tracee"
	"github.com/stretchr/testify/assert"
)

type fakeCapabilities struct {
	capability.Capabilities
	get func(capability.CapType, capability.Cap) bool
}

func (fc fakeCapabilities) Get(which capability.CapType, what capability.Cap) bool {
	if fc.get != nil {
		return fc.get(which, what)
	}
	return true
}

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
			expectedError:  errors.New("invalid filter option specified, use '--trace help' for more info"),
		},
		{
			testName:       "invalid operator",
			filters:        []string{"mntns\t0"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid filter option specified, use '--trace help' for more info"),
		},
		{
			testName:       "invalid filter type",
			filters:        []string{"UID>0"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid filter option specified, use '--trace help' for more info"),
		},
		{
			testName:       "invalid filter type",
			filters:        []string{"test=0"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid filter option specified, use '--trace help' for more info"),
		},
		{
			testName:       "invalid filter type",
			filters:        []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=0"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid filter option specified, use '--trace help' for more info"),
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
			testName:       "invalid wildcard",
			filters:        []string{"event=blah*"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid event to trace: blah*"),
		},
		{
			testName:       "invalid wildcard 2",
			filters:        []string{"event=bl*ah"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid event to trace: bl*ah"),
		},
		{
			testName:       "invalid not wildcard",
			filters:        []string{"event!=bl*ah"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid event to exclude: bl*ah"),
		},
		{
			testName:       "invalid not wildcard 2",
			filters:        []string{"event!=bl*ah"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid event to exclude: bl*ah"),
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
			testName: "wildcard filter",
			filters:  []string{"event=open*"},
			expectedFilter: tracee.Filter{
				EventsToTrace: []int32{2, 257},
				UIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
					Enabled:  false,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
					Enabled:  false,
				},
				NewPidFilter: &tracee.BoolFilter{},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Enabled:  false,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
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
			testName: "wildcard not filter",
			filters:  []string{"event!=*"},
			expectedFilter: tracee.Filter{
				EventsToTrace: []int32{},
				UIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
					Enabled:  false,
				},
				PIDFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Is32Bit:  true,
					Enabled:  false,
				},
				NewPidFilter: &tracee.BoolFilter{},
				MntNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
					Enabled:  false,
				},
				PidNSFilter: &tracee.UintFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     tracee.LessNotSetUint,
					Greater:  tracee.GreaterNotSetUint,
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
	t.Run("various capture options", func(t *testing.T) {
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
				testName:      "invalid capture dir",
				captureSlice:  []string{"dir:"},
				expectedError: errors.New("capture output dir cannot be empty"),
			},
			{
				testName:      "invalid network interface",
				captureSlice:  []string{"net=invalidnetinterface"},
				expectedError: errors.New("invalid network interface: invalidnetinterface"),
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
				testName:     "capture module",
				captureSlice: []string{"module"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					Module:     true,
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
				testName:     "multiple capture options",
				captureSlice: []string{"write", "exec", "mem", "module"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					FileWrite:  true,
					Mem:        true,
					Exec:       true,
					Module:     true,
				},
				expectedError: nil,
			},
			{
				testName:     "capture exec and enable profile",
				captureSlice: []string{"exec", "profile"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					Exec:       true,
					Profile:    true,
				},
				expectedError: nil,
			},
			{
				testName:     "just enable profile",
				captureSlice: []string{"profile"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					Exec:       true,
					Profile:    true,
				},
				expectedError: nil,
			},
			{
				testName:     "network interface",
				captureSlice: []string{"net=lo"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					NetIfaces:  []string{"lo"},
				},
			},
			{
				testName:     "network interface, but repeated",
				captureSlice: []string{"net=lo", "net=lo"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					NetIfaces:  []string{"lo"},
				},
			},
		}
		for _, tc := range testCases {
			t.Run(tc.testName, func(t *testing.T) {
				capture, err := prepareCapture(tc.captureSlice)
				if tc.expectedError == nil {
					require.NoError(t, err)
					assert.Equal(t, tc.expectedCapture, capture, tc.testName)
				} else {
					require.Equal(t, tc.expectedError, err, tc.testName)
					assert.Empty(t, capture, tc.testName)
				}
			})
		}
	})

	t.Run("clear dir", func(t *testing.T) {
		d, _ := ioutil.TempDir("", "TestPrepareCapture-*")
		capture, err := prepareCapture([]string{fmt.Sprintf("dir:%s", d), "clear-dir"})
		require.NoError(t, err)
		assert.Equal(t, tracee.CaptureConfig{OutputPath: fmt.Sprintf("%s/out", d)}, capture)
		require.NoDirExists(t, d+"out")
	})
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
			expectedOutput: tracee.OutputConfig{},
			expectedError:  errors.New("unrecognized output format: foo. Valid format values: 'table', 'table-verbose', 'json', 'gob' or 'gotemplate='. Use '--output help' for more info."),
		},
		{
			testName:       "invalid output option",
			outputSlice:    []string{"option:"},
			expectedOutput: tracee.OutputConfig{},
			expectedError:  errors.New("invalid output option: , use '--output help' for more info"),
		},
		{
			testName:       "invalid output option 2",
			outputSlice:    []string{"option:foo"},
			expectedOutput: tracee.OutputConfig{},
			expectedError:  errors.New("invalid output option: foo, use '--output help' for more info"),
		},
		{
			testName:       "empty val",
			outputSlice:    []string{"out-file"},
			expectedOutput: tracee.OutputConfig{},
			expectedError:  errors.New("unrecognized output format: out-file. Valid format values: 'table', 'table-verbose', 'json', 'gob' or 'gotemplate='. Use '--output help' for more info."),
		},
		{
			testName:    "option stack-addresses",
			outputSlice: []string{"option:stack-addresses"},
			expectedOutput: tracee.OutputConfig{
				StackAddresses: true,
				ParseArguments: true,
			},
			expectedError: nil,
		},
		{
			testName:    "option detect-syscall",
			outputSlice: []string{"option:detect-syscall"},
			expectedOutput: tracee.OutputConfig{
				DetectSyscall:  true,
				ParseArguments: true,
			},
			expectedError: nil,
		},
		{
			testName:    "option exec-env",
			outputSlice: []string{"option:exec-env"},
			expectedOutput: tracee.OutputConfig{
				ExecEnv:        true,
				ParseArguments: true,
			},
			expectedError: nil,
		},
		{
			testName:    "option exec-hash",
			outputSlice: []string{"option:exec-hash"},
			expectedOutput: tracee.OutputConfig{
				ExecHash:       true,
				ParseArguments: true,
			},
			expectedError: nil,
		},
		{
			testName:    "all options",
			outputSlice: []string{"option:stack-addresses", "option:detect-syscall", "option:exec-env", "option:exec-hash"},
			expectedOutput: tracee.OutputConfig{
				StackAddresses: true,
				DetectSyscall:  true,
				ExecEnv:        true,
				ExecHash:       true,
				ParseArguments: true,
			},
			expectedError: nil,
		},
	}
	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			output, _, err := prepareOutput(testcase.outputSlice)
			if err != nil {
				assert.Equal(t, testcase.expectedError, err)
			} else {
				assert.Equal(t, testcase.expectedOutput, output)
			}
		})
	}
}

func Test_checkCommandIsHelp(t *testing.T) {
	testCases := []struct {
		testName string
		input    []string
		expected bool
	}{
		{"no flag", []string{""}, false},
		{"help flag", []string{"help"}, true},
		{"capture flag", []string{"capture"}, false},
		{"output flag", []string{"output"}, false},
		{"trace flag", []string{"trace"}, false},
		{"multiple flags", []string{"help", "capture"}, false},
	}

	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			actual := checkCommandIsHelp(testcase.input)
			assert.Equal(t, testcase.expected, actual)
		})
	}
}

func Test_checkClangVersion(t *testing.T) {
	testCases := []struct {
		verOut        string
		expectedError string
	}{
		{
			verOut: `Ubuntu clang version 12.0.0-2
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/bin
`,
		},
		{
			verOut:        `foo bar baz invalid`,
			expectedError: "could not detect clang version from: foo bar baz invalid",
		},
		{
			verOut: `Ubuntu clang version 11.0.0-2
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/bin
`,
			expectedError: "detected clang version: 11 is older than required minimum version: 12",
		},
	}

	for _, tc := range testCases {
		err := checkClangVersion([]byte(tc.verOut))

		switch {
		case tc.expectedError != "":
			assert.EqualError(t, err, tc.expectedError)
		default:
			assert.NoError(t, err)
		}
	}
}

func Test_checkRequiredCapabilites(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		fc := fakeCapabilities{}
		require.NoError(t, checkRequiredCapabilities(fc))
	})

	t.Run("CAP_SYS_ADMIN missing", func(t *testing.T) {
		fc := fakeCapabilities{
			get: func(capType capability.CapType, c capability.Cap) bool {
				if c == capability.CAP_SYS_ADMIN {
					return false
				}
				return true
			},
		}
		require.EqualError(t, checkRequiredCapabilities(fc), "insufficient privileges to run: missing CAP_SYS_ADMIN")
	})

	t.Run("CAP_IPC_LOCK missing", func(t *testing.T) {
		fc := fakeCapabilities{
			get: func(capType capability.CapType, c capability.Cap) bool {
				if c == capability.CAP_IPC_LOCK {
					return false
				}
				return true
			},
		}
		require.EqualError(t, checkRequiredCapabilities(fc), "insufficient privileges to run: missing CAP_IPC_LOCK")
	})
}

func Test_fetchFormattedEventParams(t *testing.T) {
	testCases := []struct {
		input  int32
		output string
	}{
		{
			input:  tracee.WriteEventID,
			output: "(int fd, void* buf, size_t count)",
		},
		{
			input:  tracee.RtSigreturnEventID,
			output: "()",
		},
		{
			input:  tracee.RtSigtimedwaitEventID,
			output: "(const sigset_t* set, siginfo_t* info, const struct timespec* timeout, size_t sigsetsize)",
		},
		{
			input:  99999999, // unknown event
			output: "()",
		},
	}

	for _, tc := range testCases {
		assert.Equal(t, tc.output, fetchFormattedEventParams(tc.input))
	}
}
