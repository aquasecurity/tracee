package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/policy"
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
		policy             policy.PolicyFile
		expected           FilterMap
		skipPolicyCreation bool
	}{
		{
			testName: "global scope - single event",
			policy: policy.PolicyFile{
				Name:          "global_scope_single_event",
				Description:   "global scope - single event",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
					{Event: "write"},
				},
			},
			expected: FilterMap{
				0: {newFilterFlagBasedOn(writeFlag, "global_scope_single_event")},
			},
		},
		{
			testName: "global scope - multiple events",
			policy: policy.PolicyFile{
				Name:          "global_scope_multiple_events",
				Description:   "global scope - multiple events",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "uid_scope",
				Description:   "uid scope",
				Scope:         []string{"uid>=1000"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "pid_scope",
				Description:   "pid scope",
				Scope:         []string{"pid<=10"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "mntns",
				Description:   "mntns scope",
				Scope:         []string{"mntns=4026531840"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "pidns_scope",
				Description:   "pidns scope",
				Scope:         []string{"pidns!=4026531836"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "uts_scope",
				Description:   "uts scope",
				Scope:         []string{"uts!=ab356bc4dd554"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "comm_scope",
				Description:   "comm scope",
				Scope:         []string{"comm=bash"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "container_scope",
				Description:   "container scope",
				Scope:         []string{"container=new"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "!container_scope",
				Description:   "!container scope",
				Scope:         []string{"!container"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "container_scope",
				Description:   "container scope",
				Scope:         []string{"container"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "tree_scope",
				Description:   "tree scope",
				Scope:         []string{"tree=3213,5200"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "scope_with_space",
				Description:   "scope with space",
				Scope:         []string{"tree = 3213"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "binary_scope",
				Description:   "binary scope",
				Scope:         []string{"binary=host:/usr/bin/ls"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "bin_scope",
				Description:   "bin scope",
				Scope:         []string{"bin=4026532448:/usr/bin/ls"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "follow_scope",
				Description:   "follow scope",
				Scope:         []string{"follow"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "multiple_scope",
				Description:   "multiple scope",
				Scope:         []string{"comm=bash", "follow", "!container", "uid=1000"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			filterMap, err := PrepareFilterMapFromPolicies([]policy.PolicyFile{test.policy})
			assert.NoError(t, err)

			for k, v := range test.expected {
				assert.Equal(t, v, filterMap[k])
			}

			if !test.skipPolicyCreation {
				p, err := CreatePolicies(filterMap, false)
				assert.NotNil(t, p)
				assert.NoError(t, err)
			}
		})
	}
}

func TestPolicyEventFilter(t *testing.T) {
	tests := []struct {
		testName string
		policy   policy.PolicyFile
		expected FilterMap
	}{
		// args filter
		{
			testName: "args filter",
			policy: policy.PolicyFile{
				Name:          "args_filter",
				Description:   "args filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "return_filter",
				Description:   "return filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "timestamp_filter",
				Description:   "timestamp filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "processorId_filter",
				Description:   "processorId filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "p_filter",
				Description:   "p filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "pid_filter",
				Description:   "pid filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "processId_filter",
				Description:   "processId filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "tid_filter",
				Description:   "tid filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "threadId_filter",
				Description:   "threadId filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "ppid_filter",
				Description:   "ppid filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "parentProcessId_filter",
				Description:   "parentProcessId filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "hostTid_filter",
				Description:   "hostTid filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "hostThreadId_filter",
				Description:   "hostThreadId filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "hostPid_filter",
				Description:   "hostPid filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "hostParentProcessId_filter",
				Description:   "hostParentProcessId filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "userId_filter",
				Description:   "userId filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "mntns_filter",
				Description:   "mntns filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "mountNamespace_filter",
				Description:   "mountNamespace filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "pidns_filter",
				Description:   "pidns filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "pidNamespace_filter",
				Description:   "pidNamespace filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "processName_filter",
				Description:   "processName filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "comm_filter",
				Description:   "comm filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "hostName_filter",
				Description:   "hostName filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "cgroupId",
				Description:   "cgroupId filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "host",
				Description:   "host filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "container_filter",
				Description:   "container filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "containerId_filter",
				Description:   "containerId filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "containerImage_filter",
				Description:   "containerImage filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "containerName_filter",
				Description:   "containerName filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "podName_filter",
				Description:   "podName filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "podNamespace_filter",
				Description:   "podNamespace filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
			policy: policy.PolicyFile{
				Name:          "podUid_filter",
				Description:   "podUid filter",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []policy.Rule{
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
		// TODO: does syscall filter make sense for policy?
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			filterMap, err := PrepareFilterMapFromPolicies([]policy.PolicyFile{test.policy})
			assert.NoError(t, err)

			for k, v := range test.expected {
				assert.Equal(t, v, filterMap[k])
			}
		})
	}
}
