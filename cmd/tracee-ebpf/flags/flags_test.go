package flags_test

import (
	"errors"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/aquasecurity/tracee/cmd/tracee-ebpf/flags"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/queue"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			testName:       "internal event selection",
			filters:        []string{"event=print_syscall_table"},
			expectedFilter: tracee.Filter{},
			expectedError:  errors.New("invalid event to trace: print_syscall_table"),
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
				UIDFilter: &filters.UIntFilter{
					Equal:    []uint64{0},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
					Enabled:  true,
				},
				PIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
				},
				NewPidFilter: &filters.BoolFilter{},
				MntNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
				},
				PidNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
				},
				CommFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
				},
				UTSFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
				},
				ContFilter:    &filters.BoolFilter{},
				NewContFilter: &filters.BoolFilter{},
				ArgFilter: &filters.ArgFilter{
					Filters: map[events.ID]map[string]filters.ArgFilterVal{},
				},
				RetFilter: &filters.RetFilter{
					Filters: map[events.ID]filters.IntFilter{},
				},
			},
			expectedError: nil,
		},
		{
			testName: "uid!=0",
			filters:  []string{"uid!=0"},
			expectedFilter: tracee.Filter{
				UIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{0},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
					Enabled:  true,
				},
				PIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
				},
				NewPidFilter: &filters.BoolFilter{},
				MntNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
				},
				PidNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
				},
				CommFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
				},
				UTSFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
				},
				ContFilter:    &filters.BoolFilter{},
				NewContFilter: &filters.BoolFilter{},
				ArgFilter: &filters.ArgFilter{
					Filters: map[events.ID]map[string]filters.ArgFilterVal{},
				},
				RetFilter: &filters.RetFilter{
					Filters: map[events.ID]filters.IntFilter{},
				},
			},
			expectedError: nil,
		},
		{
			testName: "mntns=0",
			filters:  []string{"mntns=0"},
			expectedFilter: tracee.Filter{
				UIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
				},
				PIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
				},
				NewPidFilter: &filters.BoolFilter{},
				MntNSFilter: &filters.UIntFilter{
					Equal:    []uint64{0},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Enabled:  true,
				},
				PidNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
				},
				CommFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
				},
				UTSFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
				},
				ContFilter:    &filters.BoolFilter{},
				NewContFilter: &filters.BoolFilter{},
				ArgFilter: &filters.ArgFilter{
					Filters: map[events.ID]map[string]filters.ArgFilterVal{},
				},
				RetFilter: &filters.RetFilter{
					Filters: map[events.ID]filters.IntFilter{},
				},
			},
			expectedError: nil,
		},
		{
			testName: "pidns!=0",
			filters:  []string{"pidns!=0"},
			expectedFilter: tracee.Filter{
				UIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
				},
				PIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
				},
				NewPidFilter: &filters.BoolFilter{},
				MntNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
				},
				PidNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{0},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Enabled:  true,
				},
				CommFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
				},
				UTSFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
				},
				ContFilter:    &filters.BoolFilter{},
				NewContFilter: &filters.BoolFilter{},
				ArgFilter: &filters.ArgFilter{
					Filters: map[events.ID]map[string]filters.ArgFilterVal{},
				},
				RetFilter: &filters.RetFilter{
					Filters: map[events.ID]filters.IntFilter{},
				},
			},
			expectedError: nil,
		},
		{
			testName: "comm=ls",
			filters:  []string{"comm=ls"},
			expectedFilter: tracee.Filter{
				UIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
				},
				PIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
				},
				NewPidFilter: &filters.BoolFilter{},
				MntNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
				},
				PidNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
				},
				CommFilter: &filters.StringFilter{
					Equal:    []string{"ls"},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
					Enabled:  true,
				},
				UTSFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
				},
				ContFilter:    &filters.BoolFilter{},
				NewContFilter: &filters.BoolFilter{},
				ArgFilter: &filters.ArgFilter{
					Filters: map[events.ID]map[string]filters.ArgFilterVal{},
				},
				RetFilter: &filters.RetFilter{
					Filters: map[events.ID]filters.IntFilter{},
				},
			},
			expectedError: nil,
		},
		{
			testName: "uts!=deadbeaf",
			filters:  []string{"uts!=deadbeaf"},
			expectedFilter: tracee.Filter{
				UIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
				},
				PIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
				},
				NewPidFilter: &filters.BoolFilter{},
				MntNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
				},
				PidNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
				},
				CommFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
				},
				UTSFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{"deadbeaf"},
					Size:     flags.MaxBpfStrFilterSize,
					Enabled:  true,
				},
				ContFilter:    &filters.BoolFilter{},
				NewContFilter: &filters.BoolFilter{},
				ArgFilter: &filters.ArgFilter{
					Filters: map[events.ID]map[string]filters.ArgFilterVal{},
				},
				RetFilter: &filters.RetFilter{
					Filters: map[events.ID]filters.IntFilter{},
				},
			},
			expectedError: nil,
		},
		{
			testName: "uid>0",
			filters:  []string{"uid>0"},
			expectedFilter: tracee.Filter{
				UIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  0,
					Is32Bit:  true,
					Enabled:  true,
				},
				PIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
				},
				NewPidFilter: &filters.BoolFilter{},
				MntNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
				},
				PidNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
				},
				CommFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
				},
				UTSFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
				},
				ContFilter:    &filters.BoolFilter{},
				NewContFilter: &filters.BoolFilter{},
				ArgFilter: &filters.ArgFilter{
					Filters: map[events.ID]map[string]filters.ArgFilterVal{},
				},
				RetFilter: &filters.RetFilter{
					Filters: map[events.ID]filters.IntFilter{},
				},
			},
			expectedError: nil,
		},
		{
			testName: "uid<0",
			filters:  []string{"uid<0"},
			expectedFilter: tracee.Filter{
				UIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     0,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
					Enabled:  true,
				},
				PIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
				},
				NewPidFilter: &filters.BoolFilter{},
				MntNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
				},
				PidNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
				},
				CommFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
				},
				UTSFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
				},
				ContFilter:    &filters.BoolFilter{},
				NewContFilter: &filters.BoolFilter{},
				ArgFilter: &filters.ArgFilter{
					Filters: map[events.ID]map[string]filters.ArgFilterVal{},
				},
				RetFilter: &filters.RetFilter{
					Filters: map[events.ID]filters.IntFilter{},
				},
			},
			expectedError: nil,
		},
		{
			testName: "container",
			filters:  []string{"container"},
			expectedFilter: tracee.Filter{
				UIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
				},
				PIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
				},
				NewPidFilter: &filters.BoolFilter{},
				MntNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
				},
				PidNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
				},
				CommFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
				},
				UTSFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
				},
				ContFilter: &filters.BoolFilter{
					Value:   true,
					Enabled: true,
				},
				NewContFilter: &filters.BoolFilter{},
				ArgFilter: &filters.ArgFilter{
					Filters: map[events.ID]map[string]filters.ArgFilterVal{},
				},
				RetFilter: &filters.RetFilter{
					Filters: map[events.ID]filters.IntFilter{},
				},
			},
			expectedError: nil,
		},
		{
			testName: "container=new",
			filters:  []string{"container=new"},
			expectedFilter: tracee.Filter{
				UIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
				},
				PIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
				},
				NewPidFilter: &filters.BoolFilter{},
				MntNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
				},
				PidNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
				},
				CommFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
				},
				UTSFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
				},
				ContFilter: &filters.BoolFilter{},
				NewContFilter: &filters.BoolFilter{
					Value:   true,
					Enabled: true,
				},
				ArgFilter: &filters.ArgFilter{
					Filters: map[events.ID]map[string]filters.ArgFilterVal{},
				},
				RetFilter: &filters.RetFilter{
					Filters: map[events.ID]filters.IntFilter{},
				},
			},
			expectedError: nil,
		},
		{
			testName: "argfilter",
			filters:  []string{"openat.pathname=/bin/ls,/tmp/tracee", "openat.pathname!=/etc/passwd"},
			expectedFilter: tracee.Filter{
				UIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
				},
				PIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
				},
				NewPidFilter: &filters.BoolFilter{},
				MntNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
				},
				PidNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
				},
				CommFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
				},
				UTSFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
				},
				ContFilter:    &filters.BoolFilter{},
				NewContFilter: &filters.BoolFilter{},
				ArgFilter: &filters.ArgFilter{
					Filters: map[events.ID]map[string]filters.ArgFilterVal{
						events.Openat: {
							"pathname": filters.ArgFilterVal{
								Equal:    []string{"/bin/ls", "/tmp/tracee"},
								NotEqual: []string{"/etc/passwd"},
							},
						},
					},
					Enabled: true,
				},
				RetFilter: &filters.RetFilter{
					Filters: map[events.ID]filters.IntFilter{},
				},
			},
			expectedError: nil,
		},
		{
			testName: "retfilter",
			filters:  []string{"openat.retval=2", "openat.retval>1"},
			expectedFilter: tracee.Filter{
				UIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
				},
				PIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
				},
				NewPidFilter: &filters.BoolFilter{},
				MntNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
				},
				PidNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
				},
				CommFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
				},
				UTSFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
				},
				ContFilter:    &filters.BoolFilter{},
				NewContFilter: &filters.BoolFilter{},
				ArgFilter: &filters.ArgFilter{
					Filters: map[events.ID]map[string]filters.ArgFilterVal{},
				},
				RetFilter: &filters.RetFilter{
					Filters: map[events.ID]filters.IntFilter{
						events.Openat: {
							Equal:    []int64{2},
							NotEqual: []int64{},
							Less:     filters.LessNotSetInt,
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
				EventsToTrace: []events.ID{events.Open, events.Openat},
				UIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
					Enabled:  false,
				},
				PIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
					Enabled:  false,
				},
				NewPidFilter: &filters.BoolFilter{},
				MntNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Enabled:  false,
				},
				PidNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Enabled:  false,
				},
				CommFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
					Enabled:  false,
				},
				UTSFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
					Enabled:  false,
				},
				ContFilter:    &filters.BoolFilter{},
				NewContFilter: &filters.BoolFilter{},
				ArgFilter: &filters.ArgFilter{
					Filters: map[events.ID]map[string]filters.ArgFilterVal{},
				},
				RetFilter: &filters.RetFilter{
					Filters: map[events.ID]filters.IntFilter{},
				},
			},
			expectedError: nil,
		},
		{
			testName: "wildcard not filter",
			filters:  []string{"event!=*"},
			expectedFilter: tracee.Filter{
				EventsToTrace: []events.ID{},
				UIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
					Enabled:  false,
				},
				PIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
					Enabled:  false,
				},
				NewPidFilter: &filters.BoolFilter{},
				MntNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Enabled:  false,
				},
				PidNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Enabled:  false,
				},
				CommFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
					Enabled:  false,
				},
				UTSFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
					Enabled:  false,
				},
				ContFilter:    &filters.BoolFilter{},
				NewContFilter: &filters.BoolFilter{},
				ArgFilter: &filters.ArgFilter{
					Filters: map[events.ID]map[string]filters.ArgFilterVal{},
				},
				RetFilter: &filters.RetFilter{
					Filters: map[events.ID]filters.IntFilter{},
				},
			},
			expectedError: nil,
		},
		{
			testName: "multiple filters",
			filters:  []string{"uid<1", "mntns=5", "pidns!=3", "pid!=10", "comm=ps", "uts!=abc"},
			expectedFilter: tracee.Filter{
				UIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{},
					Less:     1,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
					Enabled:  true,
				},
				PIDFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{10},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Is32Bit:  true,
					Enabled:  true,
				},
				NewPidFilter: &filters.BoolFilter{},
				MntNSFilter: &filters.UIntFilter{
					Equal:    []uint64{5},
					NotEqual: []uint64{},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Enabled:  true,
				},
				PidNSFilter: &filters.UIntFilter{
					Equal:    []uint64{},
					NotEqual: []uint64{3},
					Less:     filters.LessNotSetUint,
					Greater:  filters.GreaterNotSetUint,
					Enabled:  true,
				},
				CommFilter: &filters.StringFilter{
					Equal:    []string{"ps"},
					NotEqual: []string{},
					Size:     flags.MaxBpfStrFilterSize,
					Enabled:  true,
				},
				UTSFilter: &filters.StringFilter{
					Equal:    []string{},
					NotEqual: []string{"abc"},
					Size:     flags.MaxBpfStrFilterSize,
					Enabled:  true,
				},
				ContFilter:    &filters.BoolFilter{},
				NewContFilter: &filters.BoolFilter{},
				ArgFilter: &filters.ArgFilter{
					Filters: map[events.ID]map[string]filters.ArgFilterVal{},
				},
				RetFilter: &filters.RetFilter{
					Filters: map[events.ID]filters.IntFilter{},
				},
			},
			expectedError: nil,
		},
	}
	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			filter, err := flags.PrepareFilter(testcase.filters)
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
					NetIfaces: &tracee.NetIfaces{
						Ifaces: []string{"lo"},
					},
				},
			},
			{
				testName:     "network interface, but repeated",
				captureSlice: []string{"net=lo", "net=lo"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					NetIfaces: &tracee.NetIfaces{
						Ifaces: []string{"lo"},
					},
				},
			},
		}
		for _, tc := range testCases {
			t.Run(tc.testName, func(t *testing.T) {
				capture, err := flags.PrepareCapture(tc.captureSlice)
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
		capture, err := flags.PrepareCapture([]string{fmt.Sprintf("dir:%s", d), "clear-dir"})
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
			expectedError:  errors.New("unrecognized output format: foo. Valid format values: 'table', 'table-verbose', 'json', 'gob' or 'gotemplate='. Use '--output help' for more info"),
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
			expectedError:  errors.New("unrecognized output format: out-file. Valid format values: 'table', 'table-verbose', 'json', 'gob' or 'gotemplate='. Use '--output help' for more info"),
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
			testName:    "option sort-events",
			outputSlice: []string{"option:sort-events"},
			expectedOutput: tracee.OutputConfig{
				ParseArguments: true,
				EventsSorting:  true,
			},
			expectedError: nil,
		},
		{
			testName:    "all options",
			outputSlice: []string{"option:stack-addresses", "option:detect-syscall", "option:exec-env", "option:exec-hash", "option:sort-events"},
			expectedOutput: tracee.OutputConfig{
				StackAddresses: true,
				DetectSyscall:  true,
				ExecEnv:        true,
				ExecHash:       true,
				ParseArguments: true,
				EventsSorting:  true,
			},
			expectedError: nil,
		},
	}
	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			output, _, err := flags.PrepareOutput(testcase.outputSlice)
			if err != nil {
				assert.Equal(t, testcase.expectedError, err)
			} else {
				assert.Equal(t, testcase.expectedOutput, output)
			}
		})
	}
}

func TestPrepareCache(t *testing.T) {
	testCases := []struct {
		testName      string
		cacheSlice    []string
		expectedCache queue.CacheConfig
		expectedError error
	}{
		{
			testName:      "invalid cache option",
			cacheSlice:    []string{"foo"},
			expectedCache: nil,
			expectedError: errors.New("unrecognized cache option format: foo"),
		},
		{
			testName:      "invalid cache-type",
			cacheSlice:    []string{"cache-type=bleh"},
			expectedCache: nil,
			expectedError: errors.New("unrecognized cache-mem option: cache-type=bleh (valid options are: none,mem)"),
		},
		{
			testName:      "cache-type=none",
			cacheSlice:    []string{"cache-type=none"},
			expectedCache: nil,
			expectedError: nil,
		},
		{
			testName:      "cache-type=mem",
			cacheSlice:    []string{"cache-type=mem"},
			expectedCache: queue.NewEventQueueMem(0),
			expectedError: nil,
		},
		{
			testName:      "mem-cache-size=X without cache-type=mem",
			cacheSlice:    []string{"mem-cache-size=256"},
			expectedCache: nil,
			expectedError: errors.New("you need to specify cache-type=mem before setting mem-cache-size"),
		},
		{
			testName:      "cache-type=mem with mem-cache-size=512",
			cacheSlice:    []string{"cache-type=mem", "mem-cache-size=512"},
			expectedCache: queue.NewEventQueueMem(512),
			expectedError: nil,
		},
	}

	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			cache, err := flags.PrepareCache(testcase.cacheSlice)
			assert.Equal(t, testcase.expectedError, err)
			assert.Equal(t, testcase.expectedCache, cache)
		})
	}
}
