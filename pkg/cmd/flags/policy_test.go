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
}

var readFlag = &filterFlag{
	full:              "event=read",
	filterName:        "event",
	operatorAndValues: "=read",
}

func TestPolicyScopes(t *testing.T) {
	tests := []struct {
		testName           string
		policy             policy.PolicyFile
		expected           PolicyFilterMap
		skipPolicyCreation bool
	}{
		{
			testName: "global scope - single event",
			policy: policy.PolicyFile{
				Name:           "global_scope_single_event",
				Description:    "global scope - single event",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{Event: "write"},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName:  "global_scope_single_event",
					filterFlags: []*filterFlag{writeFlag},
				},
			},
		},
		{
			testName: "global scope - multiple events",
			policy: policy.PolicyFile{
				Name:           "global_scope_multiple_events",
				Description:    "global scope - multiple events",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{Event: "write"},
					{Event: "read"},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "global_scope_multiple_events",
					filterFlags: []*filterFlag{
						writeFlag,
						readFlag,
					},
				},
			},
		},
		{
			testName: "uid scope",
			policy: policy.PolicyFile{
				Name:           "uid_scope",
				Description:    "uid scope",
				Scope:          []string{"uid>=1000"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{Event: "write"},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "uid_scope",
					filterFlags: []*filterFlag{
						{
							full:              "uid>=1000",
							filterName:        "uid",
							operatorAndValues: ">=1000",
						},
						writeFlag,
					},
				},
			},
		},
		{
			testName: "pid scope",
			policy: policy.PolicyFile{
				Name:           "pid_scope",
				Description:    "pid scope",
				Scope:          []string{"pid<=10"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{Event: "write"},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "pid_scope",
					filterFlags: []*filterFlag{
						{
							full:              "pid<=10",
							filterName:        "pid",
							operatorAndValues: "<=10",
						},
						writeFlag,
					},
				},
			},
		},
		{
			testName: "mntns scope",
			policy: policy.PolicyFile{
				Name:           "mntns",
				Description:    "mntns scope",
				Scope:          []string{"mntns=4026531840"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{Event: "write"},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "mntns",
					filterFlags: []*filterFlag{
						{
							full:              "mntns=4026531840",
							filterName:        "mntns",
							operatorAndValues: "=4026531840",
						},
						writeFlag,
					},
				},
			},
		},
		{
			testName: "pidns scope",
			policy: policy.PolicyFile{
				Name:           "pidns_scope",
				Description:    "pidns scope",
				Scope:          []string{"pidns!=4026531836"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{Event: "write"},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "pidns_scope",
					filterFlags: []*filterFlag{
						{
							full:              "pidns!=4026531836",
							filterName:        "pidns",
							operatorAndValues: "!=4026531836",
						},
						writeFlag,
					},
				},
			},
		},
		{
			testName: "uts scope",
			policy: policy.PolicyFile{
				Name:           "uts_scope",
				Description:    "uts scope",
				Scope:          []string{"uts!=ab356bc4dd554"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{Event: "write"},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "uts_scope",
					filterFlags: []*filterFlag{
						{
							full:              "uts!=ab356bc4dd554",
							filterName:        "uts",
							operatorAndValues: "!=ab356bc4dd554",
						},
						writeFlag,
					},
				},
			},
		},
		{
			testName: "comm=bash",
			policy: policy.PolicyFile{
				Name:           "comm_scope",
				Description:    "comm scope",
				Scope:          []string{"comm=bash"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{Event: "write"},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "comm_scope",
					filterFlags: []*filterFlag{
						{
							full:              "comm=bash",
							filterName:        "comm",
							operatorAndValues: "=bash",
						},
						writeFlag,
					},
				},
			},
		},
		{
			testName: "container=new",
			policy: policy.PolicyFile{
				Name:           "container_scope",
				Description:    "container scope",
				Scope:          []string{"container=new"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{Event: "write"},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "container_scope",
					filterFlags: []*filterFlag{
						{
							full:              "container=new",
							filterName:        "container",
							operatorAndValues: "=new",
						},
						writeFlag,
					},
				},
			},
		},
		{
			testName: "!container",
			policy: policy.PolicyFile{
				Name:           "!container_scope",
				Description:    "!container scope",
				Scope:          []string{"!container"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{Event: "write"},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "!container_scope",
					filterFlags: []*filterFlag{
						{
							full:              "!container",
							filterName:        "!container",
							operatorAndValues: "",
						},
						writeFlag,
					},
				},
			},
		},
		{
			testName: "container",
			policy: policy.PolicyFile{
				Name:           "container_scope",
				Description:    "container scope",
				Scope:          []string{"container"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{Event: "write"},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "container_scope",
					filterFlags: []*filterFlag{
						{
							full:              "container",
							filterName:        "container",
							operatorAndValues: "",
						},
						writeFlag,
					},
				},
			},
		},
		{
			testName: "tree=3213,5200",
			policy: policy.PolicyFile{
				Name:           "tree_scope",
				Description:    "tree scope",
				Scope:          []string{"tree=3213,5200"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{Event: "write"},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "tree_scope",
					filterFlags: []*filterFlag{
						{
							full:              "tree=3213,5200",
							filterName:        "tree",
							operatorAndValues: "=3213,5200",
						},
						writeFlag,
					},
				},
			},
		},
		{
			testName: "scope with space",
			policy: policy.PolicyFile{
				Name:           "scope_with_space",
				Description:    "scope with space",
				Scope:          []string{"tree = 3213"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{Event: "write"},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "scope_with_space",
					filterFlags: []*filterFlag{
						{
							full:              "tree=3213",
							filterName:        "tree",
							operatorAndValues: "=3213",
						},
						writeFlag,
					},
				},
			},
		},
		{
			testName: "binary=host:/usr/bin/ls",
			policy: policy.PolicyFile{
				Name:           "binary_scope",
				Description:    "binary scope",
				Scope:          []string{"binary=host:/usr/bin/ls"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{Event: "write"},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "binary_scope",
					filterFlags: []*filterFlag{
						{
							full:              "binary=host:/usr/bin/ls",
							filterName:        "binary",
							operatorAndValues: "=host:/usr/bin/ls",
						},
						writeFlag,
					},
				},
			},
			skipPolicyCreation: true, // needs root privileges
		},
		{
			testName: "bin=4026532448:/usr/bin/ls",
			policy: policy.PolicyFile{
				Name:           "bin_scope",
				Description:    "bin scope",
				Scope:          []string{"bin=4026532448:/usr/bin/ls"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{Event: "write"},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "bin_scope",
					filterFlags: []*filterFlag{
						{
							full:              "bin=4026532448:/usr/bin/ls",
							filterName:        "bin",
							operatorAndValues: "=4026532448:/usr/bin/ls",
						},
						writeFlag,
					},
				},
			},
		},
		{
			testName: "follow",
			policy: policy.PolicyFile{
				Name:           "follow_scope",
				Description:    "follow scope",
				Scope:          []string{"follow"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{Event: "write"},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "follow_scope",
					filterFlags: []*filterFlag{
						{
							full:              "follow",
							filterName:        "follow",
							operatorAndValues: "",
						},
						writeFlag,
					},
				},
			},
		},
		{
			testName: "multiple scopes",
			policy: policy.PolicyFile{
				Name:           "multiple_scope",
				Description:    "multiple scope",
				Scope:          []string{"comm=bash", "follow", "!container", "uid=1000"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{Event: "write"},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "multiple_scope",
					filterFlags: []*filterFlag{
						{
							full:              "comm=bash",
							filterName:        "comm",
							operatorAndValues: "=bash",
						},
						{
							full:              "follow",
							filterName:        "follow",
							operatorAndValues: "",
						},
						{
							full:              "!container",
							filterName:        "!container",
							operatorAndValues: "",
						},
						{
							full:              "uid=1000",
							filterName:        "uid",
							operatorAndValues: "=1000",
						},
						writeFlag,
					},
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
		expected PolicyFilterMap
	}{
		// args filter
		{
			testName: "args filter",
			policy: policy.PolicyFile{
				Name:           "args_filter",
				Description:    "args filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "security_file_open",
						Filters: []string{"args.pathname=/etc/passwd"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "args_filter",
					filterFlags: []*filterFlag{
						{
							full:              "event=security_file_open",
							filterName:        "event",
							operatorAndValues: "=security_file_open",
						},
						{
							full:              "security_file_open.args.pathname=/etc/passwd",
							filterName:        "security_file_open.args.pathname",
							operatorAndValues: "=/etc/passwd",
						},
					},
				},
			},
		},
		// return filter
		{
			testName: "return filter",
			policy: policy.PolicyFile{
				Name:           "return_filter",
				Description:    "return filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "write",
						Filters: []string{"retval=-1"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "return_filter",
					filterFlags: []*filterFlag{
						writeFlag,
						{
							full:              "write.retval=-1",
							filterName:        "write.retval",
							operatorAndValues: "=-1",
						},
					},
				},
			},
		},
		// context filter
		{
			testName: "timestamp filter",
			policy: policy.PolicyFile{
				Name:           "timestamp_filter",
				Description:    "timestamp filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "write",
						Filters: []string{"timestamp>1234567890"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "timestamp_filter",
					filterFlags: []*filterFlag{
						writeFlag,
						{
							full:              "write.context.timestamp>1234567890",
							filterName:        "write.context.timestamp",
							operatorAndValues: ">1234567890",
						},
					},
				},
			},
		},
		{
			testName: "processorId filter",
			policy: policy.PolicyFile{
				Name:           "processorId_filter",
				Description:    "processorId filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "write",
						Filters: []string{"processorId>=1234567890"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "processorId_filter",
					filterFlags: []*filterFlag{
						writeFlag,
						{
							full:              "write.context.processorId>=1234567890",
							filterName:        "write.context.processorId",
							operatorAndValues: ">=1234567890",
						},
					},
				},
			},
		},
		{
			testName: "p filter",
			policy: policy.PolicyFile{
				Name:           "p_filter",
				Description:    "p filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "write",
						Filters: []string{"p<=10"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "p_filter",
					filterFlags: []*filterFlag{
						writeFlag,
						{
							full:              "write.context.p<=10",
							filterName:        "write.context.p",
							operatorAndValues: "<=10",
						},
					},
				},
			},
		},
		{
			testName: "pid filter",
			policy: policy.PolicyFile{
				Name:           "pid_filter",
				Description:    "pid filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "write",
						Filters: []string{"pid!=1"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "pid_filter",
					filterFlags: []*filterFlag{
						writeFlag,
						{
							full:              "write.context.pid!=1",
							filterName:        "write.context.pid",
							operatorAndValues: "!=1",
						},
					},
				},
			},
		},
		{
			testName: "processId filter",
			policy: policy.PolicyFile{
				Name:           "processId_filter",
				Description:    "processId filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "write",
						Filters: []string{"processId=1387"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "processId_filter",
					filterFlags: []*filterFlag{
						writeFlag,
						{
							full:              "write.context.processId=1387",
							filterName:        "write.context.processId",
							operatorAndValues: "=1387",
						},
					},
				},
			},
		},
		{
			testName: "tid filter",
			policy: policy.PolicyFile{
				Name:           "tid_filter",
				Description:    "tid filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "write",
						Filters: []string{"tid=1388"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "tid_filter",
					filterFlags: []*filterFlag{
						writeFlag,
						{
							full:              "write.context.tid=1388",
							filterName:        "write.context.tid",
							operatorAndValues: "=1388",
						},
					},
				},
			},
		},
		{
			testName: "threadId filter",
			policy: policy.PolicyFile{
				Name:           "threadId_filter",
				Description:    "threadId filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "write",
						Filters: []string{"threadId!=1388"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "threadId_filter",
					filterFlags: []*filterFlag{
						writeFlag,
						{
							full:              "write.context.threadId!=1388",
							filterName:        "write.context.threadId",
							operatorAndValues: "!=1388",
						},
					},
				},
			},
		},
		{
			testName: "ppid filter",
			policy: policy.PolicyFile{
				Name:           "ppid_filter",
				Description:    "ppid filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "write",
						Filters: []string{"ppid=1"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "ppid_filter",
					filterFlags: []*filterFlag{
						writeFlag,
						{
							full:              "write.context.ppid=1",
							filterName:        "write.context.ppid",
							operatorAndValues: "=1",
						},
					},
				},
			},
		},
		{
			testName: "parentProcessId filter",
			policy: policy.PolicyFile{
				Name:           "parentProcessId_filter",
				Description:    "parentProcessId filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "write",
						Filters: []string{"parentProcessId>1455"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "parentProcessId_filter",
					filterFlags: []*filterFlag{
						writeFlag,
						{
							full:              "write.context.parentProcessId>1455",
							filterName:        "write.context.parentProcessId",
							operatorAndValues: ">1455",
						},
					},
				},
			},
		},
		{
			testName: "hostTid filter",
			policy: policy.PolicyFile{
				Name:           "hostTid_filter",
				Description:    "hostTid filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "read",
						Filters: []string{"hostTid=2455"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "hostTid_filter",
					filterFlags: []*filterFlag{
						readFlag,
						{
							full:              "read.context.hostTid=2455",
							filterName:        "read.context.hostTid",
							operatorAndValues: "=2455",
						},
					},
				},
			},
		},
		{
			testName: "hostThreadId filter",
			policy: policy.PolicyFile{
				Name:           "hostThreadId_filter",
				Description:    "hostThreadId filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "read",
						Filters: []string{"hostThreadId!=2455"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "hostThreadId_filter",
					filterFlags: []*filterFlag{
						readFlag,
						{
							full:              "read.context.hostThreadId!=2455",
							filterName:        "read.context.hostThreadId",
							operatorAndValues: "!=2455",
						},
					},
				},
			},
		},
		{
			testName: "hostPid filter",
			policy: policy.PolicyFile{
				Name:           "hostPid_filter",
				Description:    "hostPid filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "read",
						Filters: []string{"hostPid=333"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "hostPid_filter",
					filterFlags: []*filterFlag{
						readFlag,
						{
							full:              "read.context.hostPid=333",
							filterName:        "read.context.hostPid",
							operatorAndValues: "=333",
						},
					},
				},
			},
		},
		{
			testName: "hostParentProcessID filter",
			policy: policy.PolicyFile{
				Name:           "hostParentProcessId_filter",
				Description:    "hostParentProcessId filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "read",
						Filters: []string{"hostParentProcessId!=333"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "hostParentProcessId_filter",
					filterFlags: []*filterFlag{
						readFlag,
						{
							full:              "read.context.hostParentProcessId!=333",
							filterName:        "read.context.hostParentProcessId",
							operatorAndValues: "!=333",
						},
					},
				},
			},
		},
		{
			testName: "userId filter",
			policy: policy.PolicyFile{
				Name:           "userId_filter",
				Description:    "userId filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "read",
						Filters: []string{"userId=1000"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "userId_filter",
					filterFlags: []*filterFlag{
						readFlag,
						{
							full:              "read.context.userId=1000",
							filterName:        "read.context.userId",
							operatorAndValues: "=1000",
						},
					},
				},
			},
		},
		{
			testName: "mntns filter",
			policy: policy.PolicyFile{
				Name:           "mntns_filter",
				Description:    "mntns filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "read",
						Filters: []string{"mntns=4026531840"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "mntns_filter",
					filterFlags: []*filterFlag{
						readFlag,
						{
							full:              "read.context.mntns=4026531840",
							filterName:        "read.context.mntns",
							operatorAndValues: "=4026531840",
						},
					},
				},
			},
		},
		{
			testName: "mountNamespace filter",
			policy: policy.PolicyFile{
				Name:           "mountNamespace_filter",
				Description:    "mountNamespace filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "read",
						Filters: []string{"mountNamespace!=4026531840"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "mountNamespace_filter",
					filterFlags: []*filterFlag{
						readFlag,
						{
							full:              "read.context.mountNamespace!=4026531840",
							filterName:        "read.context.mountNamespace",
							operatorAndValues: "!=4026531840",
						},
					},
				},
			},
		},
		{
			testName: "pidns filter",
			policy: policy.PolicyFile{
				Name:           "pidns_filter",
				Description:    "pidns filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "read",
						Filters: []string{"pidns=4026531836"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "pidns_filter",
					filterFlags: []*filterFlag{
						readFlag,
						{
							full:              "read.context.pidns=4026531836",
							filterName:        "read.context.pidns",
							operatorAndValues: "=4026531836",
						},
					},
				},
			},
		},
		{
			testName: "pidNamespace filter",
			policy: policy.PolicyFile{
				Name:           "pidNamespace_filter",
				Description:    "pidNamespace filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "read",
						Filters: []string{"pidNamespace!=4026531836"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "pidNamespace_filter",
					filterFlags: []*filterFlag{
						readFlag,
						{
							full:              "read.context.pidNamespace!=4026531836",
							filterName:        "read.context.pidNamespace",
							operatorAndValues: "!=4026531836",
						},
					},
				},
			},
		},
		{
			testName: "processName filter",
			policy: policy.PolicyFile{
				Name:           "processName_filter",
				Description:    "processName filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "read",
						Filters: []string{"processName=uname"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "processName_filter",
					filterFlags: []*filterFlag{
						readFlag,
						{
							full:              "read.context.processName=uname",
							filterName:        "read.context.processName",
							operatorAndValues: "=uname",
						},
					},
				},
			},
		},
		{
			testName: "comm filter",
			policy: policy.PolicyFile{
				Name:           "comm_filter",
				Description:    "comm filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "read",
						Filters: []string{"comm!=uname"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "comm_filter",
					filterFlags: []*filterFlag{
						readFlag,
						{
							full:              "read.context.comm!=uname",
							filterName:        "read.context.comm",
							operatorAndValues: "!=uname",
						},
					},
				},
			},
		},
		{
			testName: "hostName filter",
			policy: policy.PolicyFile{
				Name:           "hostName_filter",
				Description:    "hostName filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "read",
						Filters: []string{"hostName=test"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "hostName_filter",
					filterFlags: []*filterFlag{
						readFlag,
						{
							full:              "read.context.hostName=test",
							filterName:        "read.context.hostName",
							operatorAndValues: "=test",
						},
					},
				},
			},
		},
		{
			testName: "cgroupId filter",
			policy: policy.PolicyFile{
				Name:           "cgroupId",
				Description:    "cgroupId filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "read",
						Filters: []string{"cgroupId=test"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "cgroupId",
					filterFlags: []*filterFlag{
						readFlag,
						{
							full:              "read.context.cgroupId=test",
							filterName:        "read.context.cgroupId",
							operatorAndValues: "=test",
						},
					},
				},
			},
		},
		{
			testName: "host filter",
			policy: policy.PolicyFile{
				Name:           "host",
				Description:    "host filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "read",
						Filters: []string{"host=test"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "host",
					filterFlags: []*filterFlag{
						readFlag,
						{
							full:              "read.context.host=test",
							filterName:        "read.context.host",
							operatorAndValues: "=test",
						},
					},
				},
			},
		},
		{
			testName: "container filter",
			policy: policy.PolicyFile{
				Name:           "container_filter",
				Description:    "container filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "read",
						Filters: []string{"container=c"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "container_filter",
					filterFlags: []*filterFlag{
						readFlag,
						{
							full:              "read.context.container=c",
							filterName:        "read.context.container",
							operatorAndValues: "=c",
						},
					},
				},
			},
		},
		{
			testName: "containerId filter",
			policy: policy.PolicyFile{
				Name:           "containerId_filter",
				Description:    "containerId filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "read",
						Filters: []string{"containerId=da91bf3df3dc"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "containerId_filter",
					filterFlags: []*filterFlag{
						readFlag,
						{
							full:              "read.context.containerId=da91bf3df3dc",
							filterName:        "read.context.containerId",
							operatorAndValues: "=da91bf3df3dc",
						},
					},
				},
			},
		},
		{
			testName: "containerImage filter",
			policy: policy.PolicyFile{
				Name:           "containerImage_filter",
				Description:    "containerImage filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "read",
						Filters: []string{"containerImage=tracee:latest"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "containerImage_filter",
					filterFlags: []*filterFlag{
						readFlag,
						{
							full:              "read.context.containerImage=tracee:latest",
							filterName:        "read.context.containerImage",
							operatorAndValues: "=tracee:latest",
						},
					},
				},
			},
		},
		{
			testName: "containerName filter",
			policy: policy.PolicyFile{
				Name:           "containerName_filter",
				Description:    "containerName filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "read",
						Filters: []string{"containerName=tracee"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "containerName_filter",
					filterFlags: []*filterFlag{
						readFlag,
						{
							full:              "read.context.containerName=tracee",
							filterName:        "read.context.containerName",
							operatorAndValues: "=tracee",
						},
					},
				},
			},
		},
		{
			testName: "podName filter",
			policy: policy.PolicyFile{
				Name:           "podName_filter",
				Description:    "podName filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "read",
						Filters: []string{"podName=daemonset/tracee"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "podName_filter",
					filterFlags: []*filterFlag{
						readFlag,
						{
							full:              "read.context.podName=daemonset/tracee",
							filterName:        "read.context.podName",
							operatorAndValues: "=daemonset/tracee",
						},
					},
				},
			},
		},
		{
			testName: "podNamespace filter",
			policy: policy.PolicyFile{
				Name:           "podNamespace_filter",
				Description:    "podNamespace filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "read",
						Filters: []string{"podNamespace=production"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "podNamespace_filter",
					filterFlags: []*filterFlag{
						readFlag,
						{
							full:              "read.context.podNamespace=production",
							filterName:        "read.context.podNamespace",
							operatorAndValues: "=production",
						},
					},
				},
			},
		},
		{
			testName: "podUid filter",
			policy: policy.PolicyFile{
				Name:           "podUid_filter",
				Description:    "podUid filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []policy.Rule{
					{
						Event:   "read",
						Filters: []string{"podUid=poduid"},
					},
				},
			},
			expected: PolicyFilterMap{
				0: {
					policyName: "podUid_filter",
					filterFlags: []*filterFlag{
						readFlag,
						{
							full:              "read.context.podUid=poduid",
							filterName:        "read.context.podUid",
							operatorAndValues: "=poduid",
						},
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
