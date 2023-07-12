package flags

import (
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/policy"
)

var writeEvtFlag = eventFlag{
	full:              "write",
	eventName:         "write",
	operatorAndValues: "",
}

var readEvtFlag = eventFlag{
	full:              "read",
	eventName:         "read",
	operatorAndValues: "",
}

func TestPrepareFilterMapsFromPolicies(t *testing.T) {
	tests := []struct {
		testName           string
		policy             policy.PolicyFile
		expPolicyScopeMap  PolicyScopeMap
		expPolicyEventMap  PolicyEventMap
		skipPolicyCreation bool
	}{
		//
		// scopes and events
		//
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
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "global_scope_single_event",
					scopeFlags: []scopeFlag{},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "global_scope_single_event",
					eventFlags: []eventFlag{
						writeEvtFlag,
					},
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
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "global_scope_multiple_events",
					scopeFlags: []scopeFlag{},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "global_scope_multiple_events",
					eventFlags: []eventFlag{
						writeEvtFlag,
						readEvtFlag,
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
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "uid_scope",
					scopeFlags: []scopeFlag{
						{
							full:              "uid>=1000",
							scopeName:         "uid",
							operatorAndValues: ">=1000",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "uid_scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
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
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "pid_scope",
					scopeFlags: []scopeFlag{
						{
							full:              "pid<=10",
							scopeName:         "pid",
							operatorAndValues: "<=10",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "pid_scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
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
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "mntns",
					scopeFlags: []scopeFlag{
						{
							full:              "mntns=4026531840",
							scopeName:         "mntns",
							operatorAndValues: "=4026531840",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "mntns",
					eventFlags: []eventFlag{
						writeEvtFlag,
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
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "pidns_scope",
					scopeFlags: []scopeFlag{
						{
							full:              "pidns!=4026531836",
							scopeName:         "pidns",
							operatorAndValues: "!=4026531836",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "pidns_scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
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
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "uts_scope",
					scopeFlags: []scopeFlag{
						{
							full:              "uts!=ab356bc4dd554",
							scopeName:         "uts",
							operatorAndValues: "!=ab356bc4dd554",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "uts_scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
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
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "comm_scope",
					scopeFlags: []scopeFlag{
						{
							full:              "comm=bash",
							scopeName:         "comm",
							operatorAndValues: "=bash",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "comm_scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
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
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "container_scope",
					scopeFlags: []scopeFlag{
						{
							full:              "container=new",
							scopeName:         "container",
							operatorAndValues: "=new",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "container_scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
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
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "!container_scope",
					scopeFlags: []scopeFlag{
						{
							full:              "!container",
							scopeName:         "!container",
							operatorAndValues: "",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "!container_scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
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
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "container_scope",
					scopeFlags: []scopeFlag{
						{
							full:              "container",
							scopeName:         "container",
							operatorAndValues: "",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "container_scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
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
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "tree_scope",
					scopeFlags: []scopeFlag{
						{
							full:              "tree=3213,5200",
							scopeName:         "tree",
							operatorAndValues: "=3213,5200",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "tree_scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
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
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "scope_with_space",
					scopeFlags: []scopeFlag{
						{
							full:              "tree=3213",
							scopeName:         "tree",
							operatorAndValues: "=3213",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "scope_with_space",
					eventFlags: []eventFlag{
						writeEvtFlag,
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
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "binary_scope",
					scopeFlags: []scopeFlag{
						{
							full:              "binary=host:/usr/bin/ls",
							scopeName:         "binary",
							operatorAndValues: "=host:/usr/bin/ls",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "binary_scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
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
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "bin_scope",
					scopeFlags: []scopeFlag{
						{
							full:              "bin=4026532448:/usr/bin/ls",
							scopeName:         "bin",
							operatorAndValues: "=4026532448:/usr/bin/ls",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "bin_scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
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
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "follow_scope",
					scopeFlags: []scopeFlag{
						{
							full:              "follow",
							scopeName:         "follow",
							operatorAndValues: "",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "follow_scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
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
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "multiple_scope",
					scopeFlags: []scopeFlag{
						{
							full:              "comm=bash",
							scopeName:         "comm",
							operatorAndValues: "=bash",
						},
						{
							full:              "follow",
							scopeName:         "follow",
							operatorAndValues: "",
						},
						{
							full:              "!container",
							scopeName:         "!container",
							operatorAndValues: "",
						},
						{
							full:              "uid=1000",
							scopeName:         "uid",
							operatorAndValues: "=1000",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "multiple_scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
					},
				},
			},
		},

		//
		// events
		//

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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "args_filter",
					eventFlags: []eventFlag{
						{
							full:              "security_file_open",
							eventName:         "security_file_open",
							operatorAndValues: "",
						},
						{
							full:              "security_file_open.args.pathname=/etc/passwd",
							eventName:         "security_file_open",
							eventFilter:       "security_file_open.args.pathname",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "return_filter",
					eventFlags: []eventFlag{
						writeEvtFlag,
						{
							full:              "write.retval=-1",
							eventName:         "write",
							eventFilter:       "write.retval",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "timestamp_filter",
					eventFlags: []eventFlag{
						writeEvtFlag,
						{
							full:              "write.context.timestamp>1234567890",
							eventName:         "write",
							eventFilter:       "write.context.timestamp",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "processorId_filter",
					eventFlags: []eventFlag{
						writeEvtFlag,
						{
							full:              "write.context.processorId>=1234567890",
							eventName:         "write",
							eventFilter:       "write.context.processorId",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "p_filter",
					eventFlags: []eventFlag{
						writeEvtFlag,
						{
							full:              "write.context.p<=10",
							eventName:         "write",
							eventFilter:       "write.context.p",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "pid_filter",
					eventFlags: []eventFlag{
						writeEvtFlag,
						{
							full:              "write.context.pid!=1",
							eventName:         "write",
							eventFilter:       "write.context.pid",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "processId_filter",
					eventFlags: []eventFlag{
						writeEvtFlag,
						{
							full:              "write.context.processId=1387",
							eventName:         "write",
							eventFilter:       "write.context.processId",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "tid_filter",
					eventFlags: []eventFlag{
						writeEvtFlag,
						{
							full:              "write.context.tid=1388",
							eventName:         "write",
							eventFilter:       "write.context.tid",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "threadId_filter",
					eventFlags: []eventFlag{
						writeEvtFlag,
						{
							full:              "write.context.threadId!=1388",
							eventName:         "write",
							eventFilter:       "write.context.threadId",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "ppid_filter",
					eventFlags: []eventFlag{
						writeEvtFlag,
						{
							full:              "write.context.ppid=1",
							eventName:         "write",
							eventFilter:       "write.context.ppid",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "parentProcessId_filter",
					eventFlags: []eventFlag{
						writeEvtFlag,
						{
							full:              "write.context.parentProcessId>1455",
							eventName:         "write",
							eventFilter:       "write.context.parentProcessId",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "hostTid_filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.context.hostTid=2455",
							eventName:         "read",
							eventFilter:       "read.context.hostTid",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "hostThreadId_filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.context.hostThreadId!=2455",
							eventName:         "read",
							eventFilter:       "read.context.hostThreadId",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "hostPid_filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.context.hostPid=333",
							eventName:         "read",
							eventFilter:       "read.context.hostPid",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "hostParentProcessId_filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.context.hostParentProcessId!=333",
							eventName:         "read",
							eventFilter:       "read.context.hostParentProcessId",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "userId_filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.context.userId=1000",
							eventName:         "read",
							eventFilter:       "read.context.userId",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "mntns_filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.context.mntns=4026531840",
							eventName:         "read",
							eventFilter:       "read.context.mntns",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "mountNamespace_filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.context.mountNamespace!=4026531840",
							eventName:         "read",
							eventFilter:       "read.context.mountNamespace",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "pidns_filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.context.pidns=4026531836",
							eventName:         "read",
							eventFilter:       "read.context.pidns",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "pidNamespace_filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.context.pidNamespace!=4026531836",
							eventName:         "read",
							eventFilter:       "read.context.pidNamespace",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "processName_filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.context.processName=uname",
							eventName:         "read",
							eventFilter:       "read.context.processName",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "comm_filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.context.comm!=uname",
							eventName:         "read",
							eventFilter:       "read.context.comm",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "hostName_filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.context.hostName=test",
							eventName:         "read",
							eventFilter:       "read.context.hostName",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "cgroupId",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.context.cgroupId=test",
							eventName:         "read",
							eventFilter:       "read.context.cgroupId",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "host",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.context.host=test",
							eventName:         "read",
							eventFilter:       "read.context.host",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "container_filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.context.container=c",
							eventName:         "read",
							eventFilter:       "read.context.container",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "containerId_filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.context.containerId=da91bf3df3dc",
							eventName:         "read",
							eventFilter:       "read.context.containerId",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "containerImage_filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.context.containerImage=tracee:latest",
							eventName:         "read",
							eventFilter:       "read.context.containerImage",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "containerName_filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.context.containerName=tracee",
							eventName:         "read",
							eventFilter:       "read.context.containerName",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "podName_filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.context.podName=daemonset/tracee",
							eventName:         "read",
							eventFilter:       "read.context.podName",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "podNamespace_filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.context.podNamespace=production",
							eventName:         "read",
							eventFilter:       "read.context.podNamespace",
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
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "podUid_filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.context.podUid=poduid",
							eventName:         "read",
							eventFilter:       "read.context.podUid",
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
			policyScopeMap, policyEventMap, err := PrepareFilterMapsFromPolicies([]policy.PolicyFile{test.policy})
			assert.NoError(t, err)

			for k, v := range test.expPolicyScopeMap {
				ps, ok := policyScopeMap[k]
				assert.True(t, ok)
				assert.Equal(t, v.policyName, ps.policyName)
				require.Equal(t, len(v.scopeFlags), len(ps.scopeFlags))
				for i, sf := range v.scopeFlags {
					assert.Equal(t, sf.full, ps.scopeFlags[i].full)
					assert.Equal(t, sf.scopeName, ps.scopeFlags[i].scopeName)
					assert.Equal(t, sf.operatorAndValues, ps.scopeFlags[i].operatorAndValues)
				}
			}

			for k, v := range test.expPolicyEventMap {
				pe, ok := policyEventMap[k]
				assert.True(t, ok)
				assert.Equal(t, v.policyName, pe.policyName)
				require.Equal(t, len(v.eventFlags), len(pe.eventFlags))
				for i, ef := range v.eventFlags {
					assert.Equal(t, ef.full, pe.eventFlags[i].full)
					assert.Equal(t, ef.eventName, pe.eventFlags[i].eventName)
					assert.Equal(t, ef.eventFilter, pe.eventFlags[i].eventFilter)
					assert.Equal(t, ef.operatorAndValues, pe.eventFlags[i].operatorAndValues)
				}
			}
		})
	}
}

func TestCreatePolicies(t *testing.T) {
	testCases := []struct {
		testName        string
		scopeFlags      []string
		evtFlags        []string
		expectEvtErr    error
		expectScopeErr  error
		expectPolicyErr error
	}{
		{
			testName:        "invalid argfilter 1",
			evtFlags:        []string{"open.args"},
			expectPolicyErr: filters.InvalidExpression("open."),
		},
		{
			testName:        "invalid argfilter 2",
			evtFlags:        []string{"open.args.bla=5"},
			expectPolicyErr: filters.InvalidEventArgument("bla"),
		},
		{
			testName:        "invalid argfilter 3",
			evtFlags:        []string{"open.bla=5"},
			expectPolicyErr: InvalidFilterFlagFormat("open.bla=5"),
		},
		{
			testName:        "invalid context filter 1",
			evtFlags:        []string{"open.context"},
			expectPolicyErr: filters.InvalidExpression("open.context"),
		},
		{
			testName:        "invalid context filter 2",
			evtFlags:        []string{"bla.context.processName=ls"},
			expectPolicyErr: filters.InvalidEventName("bla"),
		},
		{
			testName:        "invalid context filter 3",
			evtFlags:        []string{"openat.context.procName=ls"},
			expectPolicyErr: filters.InvalidContextField("procName"),
		},
		{
			testName:        "invalid filter",
			evtFlags:        []string{"blabla=5"},
			expectEvtErr:    InvalidFilterFlagFormat("blabla=5"),
			expectPolicyErr: InvalidFlagEmpty(),
		},
		{
			testName:        "invalid retfilter 1",
			evtFlags:        []string{".retval"},
			expectEvtErr:    InvalidFilterFlagFormat(".retval"),
			expectPolicyErr: InvalidFlagEmpty(),
		},
		{
			testName:        "invalid retfilter 2",
			evtFlags:        []string{"open.retvall=5"},
			expectPolicyErr: InvalidFilterFlagFormat("open.retvall=5"),
		},
		{
			testName:        "invalid operator",
			scopeFlags:      []string{"uid\t0"},
			expectPolicyErr: InvalidScopeOptionError("uid\t0", false),
		},
		{
			testName:        "invalid operator",
			scopeFlags:      []string{"mntns\t0"},
			expectPolicyErr: InvalidScopeOptionError("mntns\t0", false),
		},
		{
			testName:        "invalid filter type",
			scopeFlags:      []string{"UID>0"},
			expectPolicyErr: InvalidScopeOptionError("UID>0", false),
		},
		{
			testName:        "invalid filter type",
			scopeFlags:      []string{"test=0"},
			expectPolicyErr: InvalidScopeOptionError("test=0", false),
		},
		{
			testName:        "invalid filter type",
			scopeFlags:      []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=0"},
			expectPolicyErr: InvalidScopeOptionError("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=0", false),
		},
		{
			testName:        "invalid mntns 2",
			scopeFlags:      []string{"mntns=-1"},
			expectPolicyErr: filters.InvalidValue("-1"),
		},
		{
			testName:        "invalid uid 1",
			scopeFlags:      []string{"uid=4294967296"},
			expectPolicyErr: filters.InvalidValue("4294967296"),
		},
		{
			testName:        "invalid uid 2",
			scopeFlags:      []string{"uid=-1"},
			expectPolicyErr: filters.InvalidValue("-1"),
		},

		{
			testName:   "success - large uid filter",
			scopeFlags: []string{fmt.Sprintf("uid=%d", math.MaxInt32)},
		},
		{
			testName:   "success - pid greater or large",
			scopeFlags: []string{"pid>=12"},
		},
		{
			testName:   "success - uid=0",
			scopeFlags: []string{"uid=0"},
		},
		{
			testName:   "success - uid!=0",
			scopeFlags: []string{"uid!=0"},
		},
		{
			testName:   "success - mntns=0",
			scopeFlags: []string{"mntns=0"},
		},
		{
			testName:   "success - pidns!=0",
			scopeFlags: []string{"pidns!=0"},
		},
		{
			testName:   "success - comm=ls",
			scopeFlags: []string{"comm=ls"},
		},
		// requires root privileges
		// {
		// 	testName:   "success - binary=host:/usr/bin/ls",
		// 	scopeFlags: []string{"binary=host:/usr/bin/ls"},
		// },
		{
			testName:   "success - binary=/usr/bin/ls",
			scopeFlags: []string{"binary=/usr/bin/ls"},
		},
		{
			testName:   "success - uts!=deadbeaf",
			scopeFlags: []string{"uts!=deadbeaf"},
		},
		{
			testName:   "success - uid>0",
			scopeFlags: []string{"uid>0"},
		},
		{
			testName:   "container",
			scopeFlags: []string{"container"},
		},
		{
			testName:   "container=new",
			scopeFlags: []string{"container=new"},
		},
		{
			testName:   "pid=new",
			scopeFlags: []string{"pid=new"},
		},
		{
			testName:   "container=abcd123",
			scopeFlags: []string{"container=abcd123"},
		},
		{
			testName: "argfilter",
			evtFlags: []string{"openat.args.pathname=/bin/ls,/tmp/tracee", "openat.args.pathname!=/etc/passwd"},
		},
		{
			testName: "retfilter",
			evtFlags: []string{"openat.retval=2", "openat.retval>1"},
		},
		{
			testName: "wildcard filter",
			evtFlags: []string{"open*"},
		},
		{
			testName: "wildcard not filter",
			evtFlags: []string{"-*"},
		},
		{
			testName:   "multiple filters",
			scopeFlags: []string{"uid<1", "mntns=5", "pidns!=3", "pid!=10", "comm=ps", "uts!=abc"},
		},

		{
			testName:        "invalid value - string in numeric filter",
			scopeFlags:      []string{"uid=a"},
			expectPolicyErr: filters.InvalidValue("a"),
		},
		{
			testName:        "invalid pidns",
			scopeFlags:      []string{"pidns=a"},
			expectPolicyErr: filters.InvalidValue("a"),
		},

		{
			testName:   "valid pid",
			scopeFlags: []string{"pid>12"},
		},
		{
			testName: "adding retval filter then argfilter",
			evtFlags: []string{"open.retval=5", "security_file_open.args.pathname=/etc/shadow"},
		},

		{
			testName:        "invalid - uid<0",
			scopeFlags:      []string{"uid<0"},
			expectPolicyErr: filters.InvalidExpression("<0"),
		},
		{
			testName:        "invalid wildcard",
			evtFlags:        []string{"blah*"},
			expectPolicyErr: InvalidEventError("blah*"),
		},
		{
			testName:        "invalid wildcard 2",
			evtFlags:        []string{"bl*ah"},
			expectPolicyErr: InvalidEventError("bl*ah"),
		},
		{
			testName:        "internal event selection",
			evtFlags:        []string{"print_syscall_table"},
			expectPolicyErr: InvalidEventError("print_syscall_table"),
		},
		{
			testName:        "invalid not wildcard",
			evtFlags:        []string{"-blah*"},
			expectPolicyErr: InvalidEventExcludeError("blah*"),
		},
		{
			testName:        "invalid not wildcard 2",
			evtFlags:        []string{"-bl*ah"},
			expectPolicyErr: InvalidEventExcludeError("bl*ah"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			policyEventsMap, err := PrepareEventMapFromFlags(tc.evtFlags)
			if tc.expectEvtErr != nil {
				assert.ErrorContains(t, err, tc.expectEvtErr.Error())
			} else {
				assert.NoError(t, err)
			}

			policyScopeMap, err := PrepareScopeMapFromFlags(tc.scopeFlags)
			if tc.expectScopeErr != nil {
				assert.ErrorContains(t, err, tc.expectScopeErr.Error())
			} else {
				assert.NoError(t, err)
			}

			_, err = CreatePolicies(policyScopeMap, policyEventsMap, false)
			if tc.expectPolicyErr != nil {
				assert.ErrorContains(t, err, tc.expectPolicyErr.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
