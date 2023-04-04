package flags

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

var writeFlag = &filterFlag{
	full:              "event=write",
	filterName:        "event",
	operatorAndValues: "=write",
	policyIdx:         0,
}

var readFlag = &filterFlag{
	full:              "event=read",
	filterName:        "event",
	operatorAndValues: "=read",
	policyIdx:         0,
}

// newFilterFlagBasedOn returns a new filterFlag with the same values as the given
// filterFlag, but with the given policy name.
func newFilterFlagBasedOn(f *filterFlag, policyName string) *filterFlag {
	return &filterFlag{
		full:              f.full,
		filterName:        f.filterName,
		operatorAndValues: f.operatorAndValues,
		policyIdx:         0,
		policyName:        policyName,
	}
}

func TestPolicyScopes(t *testing.T) {
	tests := []struct {
		testName           string
		policy             PolicyFile
		expected           FilterMap
		skipPolicyCreation bool
	}{
		{
			testName: "global scope - single event",
			policy: PolicyFile{
				Name:          "global_scope_single_event",
				Description:   "global scope - single event",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expected: FilterMap{
				0: {newFilterFlagBasedOn(writeFlag, "global_scope_single_event")},
			},
		},
		{
			testName: "global scope - multiple events",
			policy: PolicyFile{
				Name:          "global_scope_multiple_events",
				Description:   "global scope - multiple events",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{Event: "write"},
					{Event: "read"},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(writeFlag, "global_scope_multiple_events"),
					newFilterFlagBasedOn(readFlag, "global_scope_multiple_events"),
				},
			},
		},
		{
			testName: "uid scope",
			policy: PolicyFile{
				Name:          "uid_scope",
				Description:   "uid scope",
				Scope:         []string{"uid>=1000"},
				DefaultAction: "log",
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expected: FilterMap{
				0: {
					{
						full:              "uid>=1000",
						filterName:        "uid",
						operatorAndValues: ">=1000",
						policyIdx:         0,
						policyName:        "uid_scope",
					},
					newFilterFlagBasedOn(writeFlag, "uid_scope"),
				},
			},
		},
		{
			testName: "pid scope",
			policy: PolicyFile{
				Name:          "pid_scope",
				Description:   "pid scope",
				Scope:         []string{"pid<=10"},
				DefaultAction: "log",
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expected: FilterMap{
				0: {
					{
						full:              "pid<=10",
						filterName:        "pid",
						operatorAndValues: "<=10",
						policyIdx:         0,
						policyName:        "pid_scope",
					},
					newFilterFlagBasedOn(writeFlag, "pid_scope"),
				},
			},
		},
		{
			testName: "mntns scope",
			policy: PolicyFile{
				Name:          "mntns",
				Description:   "mntns scope",
				Scope:         []string{"mntns=4026531840"},
				DefaultAction: "log",
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expected: FilterMap{
				0: {
					{
						full:              "mntns=4026531840",
						filterName:        "mntns",
						operatorAndValues: "=4026531840",
						policyIdx:         0,
						policyName:        "mntns",
					},
					newFilterFlagBasedOn(writeFlag, "mntns"),
				},
			},
		},
		{
			testName: "pidns scope",
			policy: PolicyFile{
				Name:          "pidns_scope",
				Description:   "pidns scope",
				Scope:         []string{"pidns!=4026531836"},
				DefaultAction: "log",
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expected: FilterMap{
				0: {
					{
						full:              "pidns!=4026531836",
						filterName:        "pidns",
						operatorAndValues: "!=4026531836",
						policyIdx:         0,
						policyName:        "pidns_scope",
					},
					newFilterFlagBasedOn(writeFlag, "pidns_scope"),
				},
			},
		},
		{
			testName: "uts scope",
			policy: PolicyFile{
				Name:          "uts_scope",
				Description:   "uts scope",
				Scope:         []string{"uts!=ab356bc4dd554"},
				DefaultAction: "log",
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expected: FilterMap{
				0: {
					{
						full:              "uts!=ab356bc4dd554",
						filterName:        "uts",
						operatorAndValues: "!=ab356bc4dd554",
						policyIdx:         0,
						policyName:        "uts_scope",
					},
					newFilterFlagBasedOn(writeFlag, "uts_scope"),
				},
			},
		},
		{
			testName: "comm=bash",
			policy: PolicyFile{
				Name:          "comm_scope",
				Description:   "comm scope",
				Scope:         []string{"comm=bash"},
				DefaultAction: "log",
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expected: FilterMap{
				0: {
					{
						full:              "comm=bash",
						filterName:        "comm",
						operatorAndValues: "=bash",
						policyIdx:         0,
						policyName:        "comm_scope",
					},
					newFilterFlagBasedOn(writeFlag, "comm_scope"),
				},
			},
		},
		{
			testName: "container=new",
			policy: PolicyFile{
				Name:          "container_scope",
				Description:   "container scope",
				Scope:         []string{"container=new"},
				DefaultAction: "log",
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expected: FilterMap{
				0: {
					{
						full:              "container=new",
						filterName:        "container",
						operatorAndValues: "=new",
						policyIdx:         0,
						policyName:        "container_scope",
					},
					newFilterFlagBasedOn(writeFlag, "container_scope"),
				},
			},
		},
		{
			testName: "!container",
			policy: PolicyFile{
				Name:          "!container_scope",
				Description:   "!container scope",
				Scope:         []string{"!container"},
				DefaultAction: "log",
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expected: FilterMap{
				0: {
					{
						full:              "!container",
						filterName:        "!container",
						operatorAndValues: "",
						policyIdx:         0,
						policyName:        "!container_scope",
					},
					newFilterFlagBasedOn(writeFlag, "!container_scope"),
				},
			},
		},
		{
			testName: "container",
			policy: PolicyFile{
				Name:          "container_scope",
				Description:   "container scope",
				Scope:         []string{"container"},
				DefaultAction: "log",
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expected: FilterMap{
				0: {
					{
						full:              "container",
						filterName:        "container",
						operatorAndValues: "",
						policyIdx:         0,
						policyName:        "container_scope",
					},
					newFilterFlagBasedOn(writeFlag, "container_scope"),
				},
			},
		},
		{
			testName: "tree=3213,5200",
			policy: PolicyFile{
				Name:          "tree_scope",
				Description:   "tree scope",
				Scope:         []string{"tree=3213,5200"},
				DefaultAction: "log",
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expected: FilterMap{
				0: {
					{
						full:              "tree=3213,5200",
						filterName:        "tree",
						operatorAndValues: "=3213,5200",
						policyIdx:         0,
						policyName:        "tree_scope",
					},
					newFilterFlagBasedOn(writeFlag, "tree_scope"),
				},
			},
		},
		{
			testName: "scope with space",
			policy: PolicyFile{
				Name:          "scope_with_space",
				Description:   "scope with space",
				Scope:         []string{"tree = 3213"},
				DefaultAction: "log",
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expected: FilterMap{
				0: {
					{
						full:              "tree=3213",
						filterName:        "tree",
						operatorAndValues: "=3213",
						policyIdx:         0,
						policyName:        "scope_with_space",
					},
					newFilterFlagBasedOn(writeFlag, "scope_with_space"),
				},
			},
		},
		{
			testName: "binary=host:/usr/bin/ls",
			policy: PolicyFile{
				Name:          "binary_scope",
				Description:   "binary scope",
				Scope:         []string{"binary=host:/usr/bin/ls"},
				DefaultAction: "log",
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expected: FilterMap{
				0: {
					{
						full:              "binary=host:/usr/bin/ls",
						filterName:        "binary",
						operatorAndValues: "=host:/usr/bin/ls",
						policyIdx:         0,
						policyName:        "binary_scope",
					},
					newFilterFlagBasedOn(writeFlag, "binary_scope"),
				},
			},
			skipPolicyCreation: true, // needs root privileges
		},
		{
			testName: "bin=4026532448:/usr/bin/ls",
			policy: PolicyFile{
				Name:          "bin_scope",
				Description:   "bin scope",
				Scope:         []string{"bin=4026532448:/usr/bin/ls"},
				DefaultAction: "log",
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expected: FilterMap{
				0: {
					{
						full:              "bin=4026532448:/usr/bin/ls",
						filterName:        "bin",
						operatorAndValues: "=4026532448:/usr/bin/ls",
						policyIdx:         0,
						policyName:        "bin_scope",
					},
					newFilterFlagBasedOn(writeFlag, "bin_scope"),
				},
			},
		},
		{
			testName: "follow",
			policy: PolicyFile{
				Name:          "follow_scope",
				Description:   "follow scope",
				Scope:         []string{"follow"},
				DefaultAction: "log",
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expected: FilterMap{
				0: {
					{
						full:              "follow",
						filterName:        "follow",
						operatorAndValues: "",
						policyIdx:         0,
						policyName:        "follow_scope",
					},
					newFilterFlagBasedOn(writeFlag, "follow_scope"),
				},
			},
		},
		{
			testName: "multiple scopes",
			policy: PolicyFile{
				Name:          "multiple_scope",
				Description:   "multiple scope",
				Scope:         []string{"comm=bash", "follow", "!container", "uid=1000"},
				DefaultAction: "log",
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expected: FilterMap{
				0: {
					{
						full:              "comm=bash",
						filterName:        "comm",
						operatorAndValues: "=bash",
						policyIdx:         0,
						policyName:        "multiple_scope",
					},
					{
						full:              "follow",
						filterName:        "follow",
						operatorAndValues: "",
						policyIdx:         0,
						policyName:        "multiple_scope",
					},
					{
						full:              "!container",
						filterName:        "!container",
						operatorAndValues: "",
						policyIdx:         0,
						policyName:        "multiple_scope",
					},
					{
						full:              "uid=1000",
						filterName:        "uid",
						operatorAndValues: "=1000",
						policyIdx:         0,
						policyName:        "multiple_scope",
					},
					newFilterFlagBasedOn(writeFlag, "multiple_scope"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			filterMap, err := PrepareFilterMapFromPolicies([]PolicyFile{test.policy})
			assert.NoError(t, err)

			for k, v := range test.expected {
				assert.Equal(t, v, filterMap[k])
			}

			if !test.skipPolicyCreation {
				p, err := CreatePolicies(filterMap)
				assert.NotNil(t, p)
				assert.NoError(t, err)
			}
		})
	}
}

func TestPolicyEventFilter(t *testing.T) {
	tests := []struct {
		testName string
		policy   PolicyFile
		expected FilterMap
	}{
		// args filter
		{
			testName: "args filter",
			policy: PolicyFile{
				Name:          "args_filter",
				Description:   "args filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "security_file_open",
						Filter: []string{"args.pathname=/etc/passwd"},
					},
				},
			},
			expected: FilterMap{
				0: {
					{
						full:              "event=security_file_open",
						filterName:        "event",
						operatorAndValues: "=security_file_open",
						policyIdx:         0,
						policyName:        "args_filter",
					},
					{
						full:              "security_file_open.args.pathname=/etc/passwd",
						filterName:        "security_file_open.args.pathname",
						operatorAndValues: "=/etc/passwd",
						policyIdx:         0,
						policyName:        "args_filter",
					},
				},
			},
		},
		// return filter
		{
			testName: "return filter",
			policy: PolicyFile{
				Name:          "return_filter",
				Description:   "return filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "write",
						Filter: []string{"retval=-1"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(writeFlag, "return_filter"),
					{
						full:              "write.retval=-1",
						filterName:        "write.retval",
						operatorAndValues: "=-1",
						policyIdx:         0,
						policyName:        "return_filter",
					},
				},
			},
		},
		// context filter
		{
			testName: "timestamp filter",
			policy: PolicyFile{
				Name:          "timestamp_filter",
				Description:   "timestamp filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "write",
						Filter: []string{"timestamp>1234567890"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(writeFlag, "timestamp_filter"),
					{
						full:              "write.context.timestamp>1234567890",
						filterName:        "write.context.timestamp",
						operatorAndValues: ">1234567890",
						policyIdx:         0,
						policyName:        "timestamp_filter",
					},
				},
			},
		},
		{
			testName: "processorId filter",
			policy: PolicyFile{
				Name:          "processorId_filter",
				Description:   "processorId filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "write",
						Filter: []string{"processorId>=1234567890"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(writeFlag, "processorId_filter"),
					{
						full:              "write.context.processorId>=1234567890",
						filterName:        "write.context.processorId",
						operatorAndValues: ">=1234567890",
						policyIdx:         0,
						policyName:        "processorId_filter",
					},
				},
			},
		},
		{
			testName: "p filter",
			policy: PolicyFile{
				Name:          "p_filter",
				Description:   "p filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "write",
						Filter: []string{"p<=10"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(writeFlag, "p_filter"),
					{
						full:              "write.context.p<=10",
						filterName:        "write.context.p",
						operatorAndValues: "<=10",
						policyIdx:         0,
						policyName:        "p_filter",
					},
				},
			},
		},
		{
			testName: "pid filter",
			policy: PolicyFile{
				Name:          "pid_filter",
				Description:   "pid filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "write",
						Filter: []string{"pid!=1"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(writeFlag, "pid_filter"),
					{
						full:              "write.context.pid!=1",
						filterName:        "write.context.pid",
						operatorAndValues: "!=1",
						policyIdx:         0,
						policyName:        "pid_filter",
					},
				},
			},
		},
		{
			testName: "processId filter",
			policy: PolicyFile{
				Name:          "processId_filter",
				Description:   "processId filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "write",
						Filter: []string{"processId=1387"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(writeFlag, "processId_filter"),
					{
						full:              "write.context.processId=1387",
						filterName:        "write.context.processId",
						operatorAndValues: "=1387",
						policyIdx:         0,
						policyName:        "processId_filter",
					},
				},
			},
		},
		{
			testName: "tid filter",
			policy: PolicyFile{
				Name:          "tid_filter",
				Description:   "tid filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "write",
						Filter: []string{"tid=1388"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(writeFlag, "tid_filter"),
					{
						full:              "write.context.tid=1388",
						filterName:        "write.context.tid",
						operatorAndValues: "=1388",
						policyIdx:         0,
						policyName:        "tid_filter",
					},
				},
			},
		},
		{
			testName: "threadId filter",
			policy: PolicyFile{
				Name:          "threadId_filter",
				Description:   "threadId filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "write",
						Filter: []string{"threadId!=1388"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(writeFlag, "threadId_filter"),
					{
						full:              "write.context.threadId!=1388",
						filterName:        "write.context.threadId",
						operatorAndValues: "!=1388",
						policyIdx:         0,
						policyName:        "threadId_filter",
					},
				},
			},
		},
		{
			testName: "ppid filter",
			policy: PolicyFile{
				Name:          "ppid_filter",
				Description:   "ppid filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "write",
						Filter: []string{"ppid=1"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(writeFlag, "ppid_filter"),
					{
						full:              "write.context.ppid=1",
						filterName:        "write.context.ppid",
						operatorAndValues: "=1",
						policyIdx:         0,
						policyName:        "ppid_filter",
					},
				},
			},
		},
		{
			testName: "parentProcessId filter",
			policy: PolicyFile{
				Name:          "parentProcessId_filter",
				Description:   "parentProcessId filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "write",
						Filter: []string{"parentProcessId>1455"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(writeFlag, "parentProcessId_filter"),
					{
						full:              "write.context.parentProcessId>1455",
						filterName:        "write.context.parentProcessId",
						operatorAndValues: ">1455",
						policyIdx:         0,
						policyName:        "parentProcessId_filter",
					},
				},
			},
		},
		{
			testName: "hostTid filter",
			policy: PolicyFile{
				Name:          "hostTid_filter",
				Description:   "hostTid filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "read",
						Filter: []string{"hostTid=2455"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(readFlag, "hostTid_filter"),
					{
						full:              "read.context.hostTid=2455",
						filterName:        "read.context.hostTid",
						operatorAndValues: "=2455",
						policyIdx:         0,
						policyName:        "hostTid_filter",
					},
				},
			},
		},
		{
			testName: "hostThreadId filter",
			policy: PolicyFile{
				Name:          "hostThreadId_filter",
				Description:   "hostThreadId filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "read",
						Filter: []string{"hostThreadId!=2455"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(readFlag, "hostThreadId_filter"),
					{
						full:              "read.context.hostThreadId!=2455",
						filterName:        "read.context.hostThreadId",
						operatorAndValues: "!=2455",
						policyIdx:         0,
						policyName:        "hostThreadId_filter",
					},
				},
			},
		},
		{
			testName: "hostPid filter",
			policy: PolicyFile{
				Name:          "hostPid_filter",
				Description:   "hostPid filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "read",
						Filter: []string{"hostPid=333"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(readFlag, "hostPid_filter"),
					{
						full:              "read.context.hostPid=333",
						filterName:        "read.context.hostPid",
						operatorAndValues: "=333",
						policyIdx:         0,
						policyName:        "hostPid_filter",
					},
				},
			},
		},
		{
			testName: "hostParentProcessID filter",
			policy: PolicyFile{
				Name:          "hostParentProcessId_filter",
				Description:   "hostParentProcessId filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "read",
						Filter: []string{"hostParentProcessId!=333"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(readFlag, "hostParentProcessId_filter"),
					{
						full:              "read.context.hostParentProcessId!=333",
						filterName:        "read.context.hostParentProcessId",
						operatorAndValues: "!=333",
						policyIdx:         0,
						policyName:        "hostParentProcessId_filter",
					},
				},
			},
		},
		{
			testName: "userId filter",
			policy: PolicyFile{
				Name:          "userId_filter",
				Description:   "userId filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "read",
						Filter: []string{"userId=1000"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(readFlag, "userId_filter"),
					{
						full:              "read.context.userId=1000",
						filterName:        "read.context.userId",
						operatorAndValues: "=1000",
						policyIdx:         0,
						policyName:        "userId_filter",
					},
				},
			},
		},
		{
			testName: "mntns filter",
			policy: PolicyFile{
				Name:          "mntns_filter",
				Description:   "mntns filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "read",
						Filter: []string{"mntns=4026531840"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(readFlag, "mntns_filter"),
					{
						full:              "read.context.mntns=4026531840",
						filterName:        "read.context.mntns",
						operatorAndValues: "=4026531840",
						policyIdx:         0,
						policyName:        "mntns_filter",
					},
				},
			},
		},
		{
			testName: "mountNamespace filter",
			policy: PolicyFile{
				Name:          "mountNamespace_filter",
				Description:   "mountNamespace filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "read",
						Filter: []string{"mountNamespace!=4026531840"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(readFlag, "mountNamespace_filter"),
					{
						full:              "read.context.mountNamespace!=4026531840",
						filterName:        "read.context.mountNamespace",
						operatorAndValues: "!=4026531840",
						policyIdx:         0,
						policyName:        "mountNamespace_filter",
					},
				},
			},
		},
		{
			testName: "pidns filter",
			policy: PolicyFile{
				Name:          "pidns_filter",
				Description:   "pidns filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "read",
						Filter: []string{"pidns=4026531836"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(readFlag, "pidns_filter"),
					{
						full:              "read.context.pidns=4026531836",
						filterName:        "read.context.pidns",
						operatorAndValues: "=4026531836",
						policyIdx:         0,
						policyName:        "pidns_filter",
					},
				},
			},
		},
		{
			testName: "pidNamespace filter",
			policy: PolicyFile{
				Name:          "pidNamespace_filter",
				Description:   "pidNamespace filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "read",
						Filter: []string{"pidNamespace!=4026531836"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(readFlag, "pidNamespace_filter"),
					{
						full:              "read.context.pidNamespace!=4026531836",
						filterName:        "read.context.pidNamespace",
						operatorAndValues: "!=4026531836",
						policyIdx:         0,
						policyName:        "pidNamespace_filter",
					},
				},
			},
		},
		{
			testName: "processName filter",
			policy: PolicyFile{
				Name:          "processName_filter",
				Description:   "processName filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "read",
						Filter: []string{"processName=uname"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(readFlag, "processName_filter"),
					{
						full:              "read.context.processName=uname",
						filterName:        "read.context.processName",
						operatorAndValues: "=uname",
						policyIdx:         0,
						policyName:        "processName_filter",
					},
				},
			},
		},
		{
			testName: "comm filter",
			policy: PolicyFile{
				Name:          "comm_filter",
				Description:   "comm filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "read",
						Filter: []string{"comm!=uname"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(readFlag, "comm_filter"),
					{
						full:              "read.context.comm!=uname",
						filterName:        "read.context.comm",
						operatorAndValues: "!=uname",
						policyIdx:         0,
						policyName:        "comm_filter",
					},
				},
			},
		},
		{
			testName: "hostName filter",
			policy: PolicyFile{
				Name:          "hostName_filter",
				Description:   "hostName filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "read",
						Filter: []string{"hostName=test"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(readFlag, "hostName_filter"),
					{
						full:              "read.context.hostName=test",
						filterName:        "read.context.hostName",
						operatorAndValues: "=test",
						policyIdx:         0,
						policyName:        "hostName_filter",
					},
				},
			},
		},
		{
			testName: "cgroupId filter",
			policy: PolicyFile{
				Name:          "cgroupId",
				Description:   "cgroupId filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "read",
						Filter: []string{"cgroupId=test"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(readFlag, "cgroupId"),
					{
						full:              "read.context.cgroupId=test",
						filterName:        "read.context.cgroupId",
						operatorAndValues: "=test",
						policyIdx:         0,
						policyName:        "cgroupId",
					},
				},
			},
		},
		{
			testName: "host filter",
			policy: PolicyFile{
				Name:          "host",
				Description:   "host filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "read",
						Filter: []string{"host=test"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(readFlag, "host"),
					{
						full:              "read.context.host=test",
						filterName:        "read.context.host",
						operatorAndValues: "=test",
						policyIdx:         0,
						policyName:        "host",
					},
				},
			},
		},
		{
			testName: "container filter",
			policy: PolicyFile{
				Name:          "container_filter",
				Description:   "container filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "read",
						Filter: []string{"container=c"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(readFlag, "container_filter"),
					{
						full:              "read.context.container=c",
						filterName:        "read.context.container",
						operatorAndValues: "=c",
						policyIdx:         0,
						policyName:        "container_filter",
					},
				},
			},
		},
		{
			testName: "containerId filter",
			policy: PolicyFile{
				Name:          "containerId_filter",
				Description:   "containerId filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "read",
						Filter: []string{"containerId=da91bf3df3dc"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(readFlag, "containerId_filter"),
					{
						full:              "read.context.containerId=da91bf3df3dc",
						filterName:        "read.context.containerId",
						operatorAndValues: "=da91bf3df3dc",
						policyIdx:         0,
						policyName:        "containerId_filter",
					},
				},
			},
		},
		{
			testName: "containerImage filter",
			policy: PolicyFile{
				Name:          "containerImage_filter",
				Description:   "containerImage filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "read",
						Filter: []string{"containerImage=tracee:latest"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(readFlag, "containerImage_filter"),
					{
						full:              "read.context.containerImage=tracee:latest",
						filterName:        "read.context.containerImage",
						operatorAndValues: "=tracee:latest",
						policyIdx:         0,
						policyName:        "containerImage_filter",
					},
				},
			},
		},
		{
			testName: "containerName filter",
			policy: PolicyFile{
				Name:          "containerName_filter",
				Description:   "containerName filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "read",
						Filter: []string{"containerName=tracee"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(readFlag, "containerName_filter"),
					{
						full:              "read.context.containerName=tracee",
						filterName:        "read.context.containerName",
						operatorAndValues: "=tracee",
						policyIdx:         0,
						policyName:        "containerName_filter",
					},
				},
			},
		},
		{
			testName: "podName filter",
			policy: PolicyFile{
				Name:          "podName_filter",
				Description:   "podName filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "read",
						Filter: []string{"podName=daemonset/tracee"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(readFlag, "podName_filter"),
					{
						full:              "read.context.podName=daemonset/tracee",
						filterName:        "read.context.podName",
						operatorAndValues: "=daemonset/tracee",
						policyIdx:         0,
						policyName:        "podName_filter",
					},
				},
			},
		},
		{
			testName: "podNamespace filter",
			policy: PolicyFile{
				Name:          "podNamespace_filter",
				Description:   "podNamespace filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "read",
						Filter: []string{"podNamespace=production"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(readFlag, "podNamespace_filter"),
					{
						full:              "read.context.podNamespace=production",
						filterName:        "read.context.podNamespace",
						operatorAndValues: "=production",
						policyIdx:         0,
						policyName:        "podNamespace_filter",
					},
				},
			},
		},
		{
			testName: "podUid filter",
			policy: PolicyFile{
				Name:          "podUid_filter",
				Description:   "podUid filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "read",
						Filter: []string{"podUid=poduid"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(readFlag, "podUid_filter"),
					{
						full:              "read.context.podUid=poduid",
						filterName:        "read.context.podUid",
						operatorAndValues: "=poduid",
						policyIdx:         0,
						policyName:        "podUid_filter",
					},
				},
			},
		},
		{
			testName: "filter with spaces",
			policy: PolicyFile{
				Name:          "filter_with_spaces",
				Description:   "filter with spaces",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{
						Event:  "read",
						Filter: []string{"podUid = poduid"},
					},
				},
			},
			expected: FilterMap{
				0: {
					newFilterFlagBasedOn(readFlag, "filter_with_spaces"),
					{
						full:              "read.context.podUid=poduid",
						filterName:        "read.context.podUid",
						operatorAndValues: "=poduid",
						policyIdx:         0,
						policyName:        "filter_with_spaces",
					},
				},
			},
		},
		// TODO: does syscall filter make sense for policy?
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			filterMap, err := PrepareFilterMapFromPolicies([]PolicyFile{test.policy})
			assert.NoError(t, err)

			for k, v := range test.expected {
				assert.Equal(t, v, filterMap[k])
			}

		})
	}
}

func TestPrepareFilterScopesForPolicyValidations(t *testing.T) {
	tests := []struct {
		testName            string
		policies            []PolicyFile
		expectedError       error
		expectedPolicyError bool
	}{
		{
			testName:      "empty name",
			policies:      []PolicyFile{{Name: ""}},
			expectedError: errors.New("policy name cannot be empty"),
		},
		{
			testName: "empty description",
			policies: []PolicyFile{
				{
					Name:        "empty_description",
					Description: "",
				},
			},
			expectedError: errors.New("flags.validatePolicy: policy empty_description, description cannot be empty"),
		},
		{
			testName: "empty scope",
			policies: []PolicyFile{
				{
					Name:          "empty_scope",
					Description:   "empty scope",
					Scope:         []string{},
					DefaultAction: "log",
				},
			},
			expectedError: errors.New("policy empty_scope, scope cannot be empty"),
		},
		{
			testName: "empty rules",
			policies: []PolicyFile{
				{
					Name:          "empty_rules",
					Description:   "empty rules",
					Scope:         []string{"global"},
					DefaultAction: "log",
					Rules:         []Rule{},
				},
			},
			expectedError: errors.New("policy empty_rules, rules cannot be empty"),
		},
		{
			testName: "empty event name",
			policies: []PolicyFile{
				{
					Name:          "empty_event_name",
					Description:   "empty event name",
					Scope:         []string{"global"},
					DefaultAction: "log",
					Rules: []Rule{
						{Event: ""},
					},
				},
			},
			expectedError: errors.New("flags.validateEvent: policy empty_event_name, event cannot be empty"),
		},
		{
			testName: "invalid event name",
			policies: []PolicyFile{
				{
					Name:          "invalid_event_name",
					Description:   "invalid event name",
					Scope:         []string{"global"},
					DefaultAction: "log",
					Rules: []Rule{
						{Event: "non_existing_event"},
					},
				},
			},
			expectedError: errors.New("flags.validateEvent: policy invalid_event_name, event non_existing_event is not valid"),
		},
		{
			testName: "invalid_scope_operator",
			policies: []PolicyFile{
				{
					Name:          "invalid_scope_operator",
					Description:   "invalid scope operator",
					Scope:         []string{"random"},
					DefaultAction: "log",
					Rules: []Rule{
						{Event: "write"},
					},
				},
			},
			expectedError: errors.New("flags.PrepareFilterMapFromPolicies: policy invalid_scope_operator, scope random is not valid"),
		},
		{
			testName: "invalid_scope",
			policies: []PolicyFile{
				{
					Name:          "invalid_scope",
					Description:   "invalid scope",
					Scope:         []string{"random!=0"},
					DefaultAction: "log",
					Rules: []Rule{
						{Event: "write"},
					},
				},
			},
			expectedError: errors.New("flags.validateScope: policy invalid_scope, scope random is not valid"),
		},
		{
			testName: "global scope must be unique",
			policies: []PolicyFile{
				{
					Name:          "global_scope_must_be_unique",
					Description:   "global scope must be unique",
					Scope:         []string{"global", "uid=1000"},
					DefaultAction: "log",
					Rules: []Rule{
						{Event: "write"},
					},
				},
			},
			expectedError: errors.New("policy global_scope_must_be_unique, global scope must be unique"),
		},
		{
			testName: "duplicated event",
			policies: []PolicyFile{
				{
					Name:          "duplicated_event",
					Description:   "duplicated event",
					Scope:         []string{"global"},
					DefaultAction: "log",
					Rules: []Rule{
						{Event: "write"},
						{Event: "write"},
					},
				},
			},
			expectedError: errors.New("policy duplicated_event, event write is duplicated"),
		},
		{
			testName: "invalid filter operator",
			policies: []PolicyFile{
				{
					Name:          "invalid_filter_operator",
					Description:   "invalid filter operator",
					Scope:         []string{"global"},
					DefaultAction: "log",
					Rules: []Rule{
						{
							Event: "write",
							Filter: []string{
								"random",
							},
						},
					},
				},
			},
			expectedError: errors.New("flags.PrepareFilterMapFromPolicies: invalid filter operator: random"),
		},
		{
			testName: "invalid filter",
			policies: []PolicyFile{
				{
					Name:          "invalid_filter",
					Description:   "invalid filter",
					Scope:         []string{"global"},
					DefaultAction: "log",
					Rules: []Rule{
						{
							Event: "write",
							Filter: []string{
								"random!=0",
							},
						},
					},
				},
			},
			expectedError: errors.New("flags.validateContext: policy invalid_filter, filter random is not valid"),
		},
		{
			testName: "empty policy action",
			policies: []PolicyFile{
				{
					Name:        "empty_policy_action",
					Description: "empty policy action",
					Scope:       []string{"global"},
					Rules: []Rule{
						{Event: "write"},
					},
				},
			},
			expectedError: errors.New("flags.validatePolicy: policy empty_policy_action, default action cannot be empty"),
		},
		{
			testName: "invalid policy action",
			policies: []PolicyFile{
				{
					Name:          "invalid_policy_action",
					Description:   "invalid policy action",
					Scope:         []string{"global"},
					DefaultAction: "audit",
					Rules: []Rule{
						{Event: "write"},
					},
				},
			},
			expectedError: errors.New("flags.validateAction: policy invalid_policy_action, action audit is not valid"),
		},
		{
			testName: "duplicated policy name",
			policies: []PolicyFile{
				{
					Name:          "duplicated_policy_name",
					Description:   "duplicated policy name",
					Scope:         []string{"global"},
					DefaultAction: "log",
					Rules: []Rule{
						{Event: "write"},
					},
				},
				{
					Name:          "duplicated_policy_name",
					Description:   "duplicated policy name",
					Scope:         []string{"global"},
					DefaultAction: "log",
					Rules: []Rule{
						{Event: "write"},
					},
				},
			},
			expectedError: errors.New("flags.PrepareFilterMapFromPolicies: policy duplicated_policy_name already exist"),
		},

		// invalid args?
		// invalid retval?
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			_, err := PrepareFilterMapFromPolicies(test.policies)
			if test.expectedError != nil {
				assert.ErrorContains(t, err, test.expectedError.Error())
			}
		})
	}
}
