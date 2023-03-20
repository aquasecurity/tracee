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

func TestPolicyScopes(t *testing.T) {
	tests := []struct {
		testName string
		policy   PolicyFile
		expected FilterMap
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
				0: {writeFlag},
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
					writeFlag,
					readFlag,
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
					},
					writeFlag,
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
					},
					writeFlag,
				},
			},
		},
		{
			testName: "mntNS scope",
			policy: PolicyFile{
				Name:          "mntNS_scope",
				Description:   "mntNS scope",
				Scope:         []string{"mntNS=4026531840"},
				DefaultAction: "log",
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expected: FilterMap{
				0: {
					{
						full:              "mntNS=4026531840",
						filterName:        "mntNS",
						operatorAndValues: "=4026531840",
						policyIdx:         0,
					},
					writeFlag,
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
					},
					writeFlag,
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
					},
					writeFlag,
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
					},
					writeFlag,
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
					},
					writeFlag,
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
					},
					writeFlag,
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
					},
					writeFlag,
				},
			},
		},
		{
			testName: "scope with space",
			policy: PolicyFile{
				Name:          "scpoe_with_space",
				Description:   "scope with sace",
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
					},
					writeFlag,
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
					},
					writeFlag,
				},
			},
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
					},
					writeFlag,
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
					},
					writeFlag,
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
					},
					{
						full:              "follow",
						filterName:        "follow",
						operatorAndValues: "",
						policyIdx:         0,
					},
					{
						full:              "!container",
						filterName:        "!container",
						operatorAndValues: "",
						policyIdx:         0,
					},
					{
						full:              "uid=1000",
						filterName:        "uid",
						operatorAndValues: "=1000",
						policyIdx:         0,
					},
					writeFlag,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			filterMap, err := PrepareFilterMapForPolicies([]PolicyFile{test.policy})
			assert.NoError(t, err)

			for k, v := range test.expected {
				assert.Equal(t, v, filterMap[k])
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
					},
					{
						full:              "security_file_open.args.pathname=/etc/passwd",
						filterName:        "security_file_open.args.pathname",
						operatorAndValues: "=/etc/passwd",
						policyIdx:         0,
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
					writeFlag,
					{
						full:              "write.retval=-1",
						filterName:        "write.retval",
						operatorAndValues: "=-1",
						policyIdx:         0,
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
					writeFlag,
					{
						full:              "write.context.timestamp>1234567890",
						filterName:        "write.context.timestamp",
						operatorAndValues: ">1234567890",
						policyIdx:         0,
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
					writeFlag,
					{
						full:              "write.context.processorId>=1234567890",
						filterName:        "write.context.processorId",
						operatorAndValues: ">=1234567890",
						policyIdx:         0,
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
					writeFlag,
					{
						full:              "write.context.p<=10",
						filterName:        "write.context.p",
						operatorAndValues: "<=10",
						policyIdx:         0,
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
					writeFlag,
					{
						full:              "write.context.pid!=1",
						filterName:        "write.context.pid",
						operatorAndValues: "!=1",
						policyIdx:         0,
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
					writeFlag,
					{
						full:              "write.context.processId=1387",
						filterName:        "write.context.processId",
						operatorAndValues: "=1387",
						policyIdx:         0,
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
					writeFlag,
					{
						full:              "write.context.tid=1388",
						filterName:        "write.context.tid",
						operatorAndValues: "=1388",
						policyIdx:         0,
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
					writeFlag,
					{
						full:              "write.context.threadId!=1388",
						filterName:        "write.context.threadId",
						operatorAndValues: "!=1388",
						policyIdx:         0,
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
					writeFlag,
					{
						full:              "write.context.ppid=1",
						filterName:        "write.context.ppid",
						operatorAndValues: "=1",
						policyIdx:         0,
					},
				},
			},
		},
		{
			testName: " filter",
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
					writeFlag,
					{
						full:              "write.context.parentProcessId>1455",
						filterName:        "write.context.parentProcessId",
						operatorAndValues: ">1455",
						policyIdx:         0,
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
					readFlag,
					{
						full:              "read.context.hostTid=2455",
						filterName:        "read.context.hostTid",
						operatorAndValues: "=2455",
						policyIdx:         0,
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
					readFlag,
					{
						full:              "read.context.hostThreadId!=2455",
						filterName:        "read.context.hostThreadId",
						operatorAndValues: "!=2455",
						policyIdx:         0,
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
					readFlag,
					{
						full:              "read.context.hostPid=333",
						filterName:        "read.context.hostPid",
						operatorAndValues: "=333",
						policyIdx:         0,
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
					readFlag,
					{
						full:              "read.context.hostParentProcessId!=333",
						filterName:        "read.context.hostParentProcessId",
						operatorAndValues: "!=333",
						policyIdx:         0,
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
					readFlag,
					{
						full:              "read.context.userId=1000",
						filterName:        "read.context.userId",
						operatorAndValues: "=1000",
						policyIdx:         0,
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
					readFlag,
					{
						full:              "read.context.mntns=4026531840",
						filterName:        "read.context.mntns",
						operatorAndValues: "=4026531840",
						policyIdx:         0,
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
					readFlag,
					{
						full:              "read.context.mountNamespace!=4026531840",
						filterName:        "read.context.mountNamespace",
						operatorAndValues: "!=4026531840",
						policyIdx:         0,
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
					readFlag,
					{
						full:              "read.context.pidns=4026531836",
						filterName:        "read.context.pidns",
						operatorAndValues: "=4026531836",
						policyIdx:         0,
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
					readFlag,
					{
						full:              "read.context.pidNamespace!=4026531836",
						filterName:        "read.context.pidNamespace",
						operatorAndValues: "!=4026531836",
						policyIdx:         0,
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
					readFlag,
					{
						full:              "read.context.processName=uname",
						filterName:        "read.context.processName",
						operatorAndValues: "=uname",
						policyIdx:         0,
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
					readFlag,
					{
						full:              "read.context.comm!=uname",
						filterName:        "read.context.comm",
						operatorAndValues: "!=uname",
						policyIdx:         0,
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
					readFlag,
					{
						full:              "read.context.hostName=test",
						filterName:        "read.context.hostName",
						operatorAndValues: "=test",
						policyIdx:         0,
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
					readFlag,
					{
						full:              "read.context.cgroupId=test",
						filterName:        "read.context.cgroupId",
						operatorAndValues: "=test",
						policyIdx:         0,
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
					readFlag,
					{
						full:              "read.context.host=test",
						filterName:        "read.context.host",
						operatorAndValues: "=test",
						policyIdx:         0,
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
					readFlag,
					{
						full:              "read.context.container=c",
						filterName:        "read.context.container",
						operatorAndValues: "=c",
						policyIdx:         0,
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
					readFlag,
					{
						full:              "read.context.containerId=da91bf3df3dc",
						filterName:        "read.context.containerId",
						operatorAndValues: "=da91bf3df3dc",
						policyIdx:         0,
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
					readFlag,
					{
						full:              "read.context.containerImage=tracee:latest",
						filterName:        "read.context.containerImage",
						operatorAndValues: "=tracee:latest",
						policyIdx:         0,
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
					readFlag,
					{
						full:              "read.context.containerName=tracee",
						filterName:        "read.context.containerName",
						operatorAndValues: "=tracee",
						policyIdx:         0,
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
					readFlag,
					{
						full:              "read.context.podName=daemonset/tracee",
						filterName:        "read.context.podName",
						operatorAndValues: "=daemonset/tracee",
						policyIdx:         0,
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
					readFlag,
					{
						full:              "read.context.podNamespace=production",
						filterName:        "read.context.podNamespace",
						operatorAndValues: "=production",
						policyIdx:         0,
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
					readFlag,
					{
						full:              "read.context.podUid=poduid",
						filterName:        "read.context.podUid",
						operatorAndValues: "=poduid",
						policyIdx:         0,
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
					readFlag,
					{
						full:              "read.context.podUid=poduid",
						filterName:        "read.context.podUid",
						operatorAndValues: "=poduid",
						policyIdx:         0,
					},
				},
			},
		},
		// TODO: does syscall filter make sense for policy?
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			filterMap, err := PrepareFilterMapForPolicies([]PolicyFile{test.policy})
			assert.NoError(t, err)

			for k, v := range test.expected {
				assert.Equal(t, v, filterMap[k])
			}

		})
	}
}

func TestPrepareFilterScopesForPolicyValidations(t *testing.T) {
	tests := []struct {
		testName      string
		policy        PolicyFile
		expectedError error
	}{
		{
			testName:      "empty name",
			policy:        PolicyFile{Name: ""},
			expectedError: errors.New("policy name cannot be empty"),
		},
		{
			testName: "empty description",
			policy: PolicyFile{
				Name:        "empty_descritpion",
				Description: "",
			},
			expectedError: errors.New("flags.validatePolicy: policy empty_descritpion, description cannot be empty"),
		},
		{
			testName: "empty scope",
			policy: PolicyFile{
				Name:          "empty_scope",
				Description:   "empty scope",
				Scope:         []string{},
				DefaultAction: "log",
			},
			expectedError: errors.New("policy empty_scope, scope cannot be empty"),
		},
		{
			testName: "empty rules",
			policy: PolicyFile{
				Name:          "empty_rules",
				Description:   "empty rules",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules:         []Rule{},
			},
			expectedError: errors.New("policy empty_rules, rules cannot be empty"),
		},
		{
			testName: "empty event name",
			policy: PolicyFile{
				Name:          "empty_event_name",
				Description:   "empty event name",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{Event: ""},
				},
			},
			expectedError: errors.New("flags.validateEvent: policy empty_event_name, event cannot be empty"),
		},
		{
			testName: "invalid event name",
			policy: PolicyFile{
				Name:          "invalid_event_name",
				Description:   "invalid event name",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{Event: "non_existing_event"},
				},
			},
			expectedError: errors.New("flags.validateEvent: policy invalid_event_name, event non_existing_event is not valid"),
		},
		{
			testName: "invalid_scope_operator",
			policy: PolicyFile{
				Name:          "invalid_scope_operator",
				Description:   "invalid scope operator",
				Scope:         []string{"random"},
				DefaultAction: "log",
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expectedError: errors.New("flags.PrepareFilterMapForPolicies: policy invalid_scope_operator, scope random is not valid"),
		},
		{
			testName: "invalid_scope",
			policy: PolicyFile{
				Name:          "invalid_scope",
				Description:   "invalid scope",
				Scope:         []string{"random!=0"},
				DefaultAction: "log",
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expectedError: errors.New("flags.validateScope: policy invalid_scope, scope random is not valid"),
		},
		{
			testName: "global scope must be unique",
			policy: PolicyFile{
				Name:          "global_scope_must_be_unique",
				Description:   "global scope must be unique",
				Scope:         []string{"global", "uid=1000"},
				DefaultAction: "log",
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expectedError: errors.New("policy global_scope_must_be_unique, global scope must be unique"),
		},
		{
			testName: "duplicated event",
			policy: PolicyFile{
				Name:          "duplicated_event",
				Description:   "duplicated event",
				Scope:         []string{"global"},
				DefaultAction: "log",
				Rules: []Rule{
					{Event: "write"},
					{Event: "write"},
				},
			},
			expectedError: errors.New("policy duplicated_event, event write is duplicated"),
		},
		{
			testName: "invalid filter operator",
			policy: PolicyFile{
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
			expectedError: errors.New("flags.PrepareFilterMapForPolicies: invalid filter: random"),
		},
		{
			testName: "invalid filter",
			policy: PolicyFile{
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
			expectedError: errors.New("flags.validateContext: policy invalid_filter, filter random is not valid"),
		},
		{
			testName: "empty policy action",
			policy: PolicyFile{
				Name:        "empty_policy_action",
				Description: "empty policy action",
				Scope:       []string{"global"},
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expectedError: errors.New("flags.validatePolicy: policy empty_policy_action, default action cannot be empty"),
		},
		{
			testName: "invalid policy action",
			policy: PolicyFile{
				Name:          "invalid_policy_action",
				Description:   "invalid policy action",
				Scope:         []string{"global"},
				DefaultAction: "audit",
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expectedError: errors.New("flags.validateAction: policy invalid_policy_action, action audit is not valid"),
		},

		// invalid args?
		// invalid retval?
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			_, err := PrepareFilterMapForPolicies([]PolicyFile{test.policy})
			if test.expectedError != nil {
				assert.ErrorContains(t, err, test.expectedError.Error())
			}
		})
	}
}
