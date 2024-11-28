package flags

import (
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	k8s "github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/policy/v1beta1"
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
	t.Parallel()

	description := map[string]string{"description": "this is a policy"}
	tests := []struct {
		testName           string
		policy             v1beta1.PolicyFile
		expPolicyScopeMap  PolicyScopeMap
		expPolicyEventMap  PolicyEventMap
		skipPolicyCreation bool
	}{
		//
		// scopes and events
		//
		{
			testName: "global scope - single event",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name:        "global-scope-single-event",
					Annotations: description,
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{Event: "write"},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "global-scope-single-event",
					scopeFlags: []scopeFlag{},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "global-scope-single-event",
					eventFlags: []eventFlag{
						writeEvtFlag,
					},
				},
			},
		},
		{
			testName: "global scope - multiple events",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "global-scope-multiple-events",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{Event: "write"},
						{Event: "read"},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "global-scope-multiple-events",
					scopeFlags: []scopeFlag{},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "global-scope-multiple-events",
					eventFlags: []eventFlag{
						writeEvtFlag,
						readEvtFlag,
					},
				},
			},
		},
		{
			testName: "uid scope",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "uid-scope",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"uid>=1000"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{Event: "write"},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "uid-scope",
					scopeFlags: []scopeFlag{
						{
							full:              "uid>=1000",
							scopeName:         "uid",
							operator:          ">=",
							values:            "1000",
							operatorAndValues: ">=1000",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "uid-scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
					},
				},
			},
		},
		{
			testName: "pid scope",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "pid-scope",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"pid<=10"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{Event: "write"},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "pid-scope",
					scopeFlags: []scopeFlag{
						{
							full:              "pid<=10",
							scopeName:         "pid",
							operator:          "<=",
							values:            "10",
							operatorAndValues: "<=10",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "pid-scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
					},
				},
			},
		},
		{
			testName: "mntns scope",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "mntns",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"mntns=4026531840"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{Event: "write"},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "mntns",
					scopeFlags: []scopeFlag{
						{
							full:              "mntns=4026531840",
							scopeName:         "mntns",
							operator:          "=",
							values:            "4026531840",
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
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "pidns-scope",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"pidns!=4026531836"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{Event: "write"},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "pidns-scope",
					scopeFlags: []scopeFlag{
						{
							full:              "pidns!=4026531836",
							scopeName:         "pidns",
							operator:          "!=",
							values:            "4026531836",
							operatorAndValues: "!=4026531836",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "pidns-scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
					},
				},
			},
		},
		{
			testName: "uts scope",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "uts-scope",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"uts!=ab356bc4dd554"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{Event: "write"},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "uts-scope",
					scopeFlags: []scopeFlag{
						{
							full:              "uts!=ab356bc4dd554",
							scopeName:         "uts",
							operator:          "!=",
							values:            "ab356bc4dd554",
							operatorAndValues: "!=ab356bc4dd554",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "uts-scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
					},
				},
			},
		},
		{
			testName: "comm=bash",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "comm-scope",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"comm=bash"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{Event: "write"},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "comm-scope",
					scopeFlags: []scopeFlag{
						{
							full:              "comm=bash",
							scopeName:         "comm",
							operator:          "=",
							values:            "bash",
							operatorAndValues: "=bash",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "comm-scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
					},
				},
			},
		},
		{
			testName: "container=new",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "container-scope",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"container=new"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{Event: "write"},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "container-scope",
					scopeFlags: []scopeFlag{
						{
							full:              "container=new",
							scopeName:         "container",
							operator:          "=",
							values:            "new",
							operatorAndValues: "=new",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "container-scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
					},
				},
			},
		},
		{
			testName: "not-container",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "not-container-scope",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"not-container"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{Event: "write"},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "not-container-scope",
					scopeFlags: []scopeFlag{
						{
							full:              "not-container",
							scopeName:         "container",
							operator:          "not",
							values:            "",
							operatorAndValues: "",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "not-container-scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
					},
				},
			},
		},
		{
			testName: "container",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "container-scope",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"container"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{Event: "write"},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "container-scope",
					scopeFlags: []scopeFlag{
						{
							full:              "container",
							scopeName:         "container",
							operator:          "",
							values:            "",
							operatorAndValues: "",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "container-scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
					},
				},
			},
		},
		{
			testName: "tree=3213,5200",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "tree-scope",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"tree=3213,5200"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{Event: "write"},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "tree-scope",
					scopeFlags: []scopeFlag{
						{
							full:              "tree=3213,5200",
							scopeName:         "tree",
							operator:          "=",
							values:            "3213,5200",
							operatorAndValues: "=3213,5200",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "tree-scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
					},
				},
			},
		},
		{
			testName: "scope with space",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "scope-with-space",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"tree = 3213"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{Event: "write"},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "scope-with-space",
					scopeFlags: []scopeFlag{
						{
							full:              "tree=3213",
							scopeName:         "tree",
							operator:          "=",
							values:            "3213",
							operatorAndValues: "=3213",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "scope-with-space",
					eventFlags: []eventFlag{
						writeEvtFlag,
					},
				},
			},
		},
		{
			testName: "executable=host:/usr/bin/ls",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "executable-scope",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"executable=host:/usr/bin/ls"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{Event: "write"},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "executable-scope",
					scopeFlags: []scopeFlag{
						{
							full:              "executable=host:/usr/bin/ls",
							scopeName:         "executable",
							operator:          "=",
							values:            "host:/usr/bin/ls",
							operatorAndValues: "=host:/usr/bin/ls",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "executable-scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
					},
				},
			},
			skipPolicyCreation: true, // needs root privileges
		},
		{
			testName: "exec=4026532448:/usr/bin/ls",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "exec-scope",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"exec=4026532448:/usr/bin/ls"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{Event: "write"},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "exec-scope",
					scopeFlags: []scopeFlag{
						{
							full:              "exec=4026532448:/usr/bin/ls",
							scopeName:         "exec",
							operator:          "=",
							values:            "4026532448:/usr/bin/ls",
							operatorAndValues: "=4026532448:/usr/bin/ls",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "exec-scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
					},
				},
			},
		},
		{
			testName: "bin=4026532448:/usr/bin/ls",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "exec-scope (bin alias)",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"bin=4026532448:/usr/bin/ls"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{Event: "write"},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "exec-scope (bin alias)",
					scopeFlags: []scopeFlag{
						{
							full:              "bin=4026532448:/usr/bin/ls",
							scopeName:         "bin",
							operator:          "=",
							values:            "4026532448:/usr/bin/ls",
							operatorAndValues: "=4026532448:/usr/bin/ls",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "exec-scope (bin alias)",
					eventFlags: []eventFlag{
						writeEvtFlag,
					},
				},
			},
		},
		{
			testName: "follow",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "follow-scope",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"follow"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{Event: "write"},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "follow-scope",
					scopeFlags: []scopeFlag{
						{
							full:              "follow",
							scopeName:         "follow",
							operator:          "",
							values:            "",
							operatorAndValues: "",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "follow-scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
					},
				},
			},
		},
		{
			testName: "multiple scopes",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "multiple-scope",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"comm=bash", "follow", "not-container", "uid=1000"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{Event: "write"},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{
				0: {
					policyName: "multiple-scope",
					scopeFlags: []scopeFlag{
						{
							full:              "comm=bash",
							scopeName:         "comm",
							operator:          "=",
							values:            "bash",
							operatorAndValues: "=bash",
						},
						{
							full:              "follow",
							scopeName:         "follow",
							operator:          "",
							values:            "",
							operatorAndValues: "",
						},
						{
							full:              "not-container",
							scopeName:         "container",
							operator:          "not",
							values:            "",
							operatorAndValues: "",
						},
						{
							full:              "uid=1000",
							scopeName:         "uid",
							operator:          "=",
							values:            "1000",
							operatorAndValues: "=1000",
						},
					},
				},
			},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "multiple-scope",
					eventFlags: []eventFlag{
						writeEvtFlag,
					},
				},
			},
		},

		//
		// events
		//

		// data filter
		{
			testName: "data filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "data-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "security_file_open",
							Filters: []string{"data.pathname=/etc/passwd"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "data-filter",
					eventFlags: []eventFlag{
						{
							full:              "security_file_open",
							eventName:         "security_file_open",
							operatorAndValues: "",
						},
						{
							full:              "security_file_open.data.pathname=/etc/passwd",
							eventName:         "security_file_open",
							eventFilter:       "security_file_open.data.pathname",
							operatorAndValues: "=/etc/passwd",
						},
					},
				},
			},
		},
		// keep a single args (deprecated) filter test that shall break on future removal
		{
			testName: "args filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "args-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "security_file_open",
							Filters: []string{"args.pathname=/etc/passwd"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "args-filter",
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
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "return-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "write",
							Filters: []string{"retval=-1"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "return-filter",
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
		// scope filter
		{
			testName: "timestamp filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "timestamp-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "write",
							Filters: []string{"timestamp>1234567890"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "timestamp-filter",
					eventFlags: []eventFlag{
						writeEvtFlag,
						{
							full:              "write.scope.timestamp>1234567890",
							eventName:         "write",
							eventFilter:       "write.scope.timestamp",
							operatorAndValues: ">1234567890",
						},
					},
				},
			},
		},
		{
			testName: "processorId filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "processorId-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "write",
							Filters: []string{"processorId>=1234567890"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "processorId-filter",
					eventFlags: []eventFlag{
						writeEvtFlag,
						{
							full:              "write.scope.processorId>=1234567890",
							eventName:         "write",
							eventFilter:       "write.scope.processorId",
							operatorAndValues: ">=1234567890",
						},
					},
				},
			},
		},
		{
			testName: "p filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "p-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "write",
							Filters: []string{"p<=10"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "p-filter",
					eventFlags: []eventFlag{
						writeEvtFlag,
						{
							full:              "write.scope.p<=10",
							eventName:         "write",
							eventFilter:       "write.scope.p",
							operatorAndValues: "<=10",
						},
					},
				},
			},
		},
		{
			testName: "pid filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "pid-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "write",
							Filters: []string{"pid!=1"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "pid-filter",
					eventFlags: []eventFlag{
						writeEvtFlag,
						{
							full:              "write.scope.pid!=1",
							eventName:         "write",
							eventFilter:       "write.scope.pid",
							operatorAndValues: "!=1",
						},
					},
				},
			},
		},
		{
			testName: "processId filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "processId-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "write",
							Filters: []string{"processId=1387"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "processId-filter",
					eventFlags: []eventFlag{
						writeEvtFlag,
						{
							full:              "write.scope.processId=1387",
							eventName:         "write",
							eventFilter:       "write.scope.processId",
							operatorAndValues: "=1387",
						},
					},
				},
			},
		},
		{
			testName: "tid filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "tid-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "write",
							Filters: []string{"tid=1388"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "tid-filter",
					eventFlags: []eventFlag{
						writeEvtFlag,
						{
							full:              "write.scope.tid=1388",
							eventName:         "write",
							eventFilter:       "write.scope.tid",
							operatorAndValues: "=1388",
						},
					},
				},
			},
		},
		{
			testName: "threadId filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "threadId-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "write",
							Filters: []string{"threadId!=1388"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "threadId-filter",
					eventFlags: []eventFlag{
						writeEvtFlag,
						{
							full:              "write.scope.threadId!=1388",
							eventName:         "write",
							eventFilter:       "write.scope.threadId",
							operatorAndValues: "!=1388",
						},
					},
				},
			},
		},
		{
			testName: "ppid filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "ppid_filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "write",
							Filters: []string{"ppid=1"},
						},
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
							full:              "write.scope.ppid=1",
							eventName:         "write",
							eventFilter:       "write.scope.ppid",
							operatorAndValues: "=1",
						},
					},
				},
			},
		},
		{
			testName: "parentProcessId filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "parentProcessId-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "write",
							Filters: []string{"parentProcessId>1455"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "parentProcessId-filter",
					eventFlags: []eventFlag{
						writeEvtFlag,
						{
							full:              "write.scope.parentProcessId>1455",
							eventName:         "write",
							eventFilter:       "write.scope.parentProcessId",
							operatorAndValues: ">1455",
						},
					},
				},
			},
		},
		{
			testName: "hostTid filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "hostTid-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "read",
							Filters: []string{"hostTid=2455"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "hostTid-filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.scope.hostTid=2455",
							eventName:         "read",
							eventFilter:       "read.scope.hostTid",
							operatorAndValues: "=2455",
						},
					},
				},
			},
		},
		{
			testName: "hostThreadId filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "hostThreadId-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "read",
							Filters: []string{"hostThreadId!=2455"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "hostThreadId-filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.scope.hostThreadId!=2455",
							eventName:         "read",
							eventFilter:       "read.scope.hostThreadId",
							operatorAndValues: "!=2455",
						},
					},
				},
			},
		},
		{
			testName: "hostPid filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "hostPid-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "read",
							Filters: []string{"hostPid=333"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "hostPid-filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.scope.hostPid=333",
							eventName:         "read",
							eventFilter:       "read.scope.hostPid",
							operatorAndValues: "=333",
						},
					},
				},
			},
		},
		{
			testName: "hostParentProcessID filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "hostParentProcessId-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "read",
							Filters: []string{"hostParentProcessId!=333"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "hostParentProcessId-filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.scope.hostParentProcessId!=333",
							eventName:         "read",
							eventFilter:       "read.scope.hostParentProcessId",
							operatorAndValues: "!=333",
						},
					},
				},
			},
		},
		{
			testName: "userId filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "userId-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "read",
							Filters: []string{"userId=1000"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "userId-filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.scope.userId=1000",
							eventName:         "read",
							eventFilter:       "read.scope.userId",
							operatorAndValues: "=1000",
						},
					},
				},
			},
		},
		{
			testName: "mntns filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "mntns-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "read",
							Filters: []string{"mntns=4026531840"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "mntns-filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.scope.mntns=4026531840",
							eventName:         "read",
							eventFilter:       "read.scope.mntns",
							operatorAndValues: "=4026531840",
						},
					},
				},
			},
		},
		{
			testName: "mountNamespace filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "mountNamespace-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "read",
							Filters: []string{"mountNamespace!=4026531840"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "mountNamespace-filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.scope.mountNamespace!=4026531840",
							eventName:         "read",
							eventFilter:       "read.scope.mountNamespace",
							operatorAndValues: "!=4026531840",
						},
					},
				},
			},
		},
		{
			testName: "pidns filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "pidns-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "read",
							Filters: []string{"pidns=4026531836"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "pidns-filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.scope.pidns=4026531836",
							eventName:         "read",
							eventFilter:       "read.scope.pidns",
							operatorAndValues: "=4026531836",
						},
					},
				},
			},
		},
		{
			testName: "pidNamespace filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "pidNamespace-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "read",
							Filters: []string{"pidNamespace!=4026531836"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "pidNamespace-filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.scope.pidNamespace!=4026531836",
							eventName:         "read",
							eventFilter:       "read.scope.pidNamespace",
							operatorAndValues: "!=4026531836",
						},
					},
				},
			},
		},
		{
			testName: "processName filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "processName-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "read",
							Filters: []string{"processName=uname"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "processName-filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.scope.processName=uname",
							eventName:         "read",
							eventFilter:       "read.scope.processName",
							operatorAndValues: "=uname",
						},
					},
				},
			},
		},
		{
			testName: "comm filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "comm-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "read",
							Filters: []string{"comm!=uname"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "comm-filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.scope.comm!=uname",
							eventName:         "read",
							eventFilter:       "read.scope.comm",
							operatorAndValues: "!=uname",
						},
					},
				},
			},
		},
		{
			testName: "hostName filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "hostName-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "read",
							Filters: []string{"hostName=test"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "hostName-filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.scope.hostName=test",
							eventName:         "read",
							eventFilter:       "read.scope.hostName",
							operatorAndValues: "=test",
						},
					},
				},
			},
		},
		{
			testName: "cgroupId filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "cgroupId",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "read",
							Filters: []string{"cgroupId=test"},
						},
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
							full:              "read.scope.cgroupId=test",
							eventName:         "read",
							eventFilter:       "read.scope.cgroupId",
							operatorAndValues: "=test",
						},
					},
				},
			},
		},
		{
			testName: "host filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "host",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "read",
							Filters: []string{"host=test"},
						},
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
							full:              "read.scope.host=test",
							eventName:         "read",
							eventFilter:       "read.scope.host",
							operatorAndValues: "=test",
						},
					},
				},
			},
		},
		{
			testName: "container filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "container-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "read",
							Filters: []string{"container=c"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "container-filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.scope.container=c",
							eventName:         "read",
							eventFilter:       "read.scope.container",
							operatorAndValues: "=c",
						},
					},
				},
			},
		},
		{
			testName: "containerId filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "containerId-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "read",
							Filters: []string{"containerId=da91bf3df3dc"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "containerId-filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.scope.containerId=da91bf3df3dc",
							eventName:         "read",
							eventFilter:       "read.scope.containerId",
							operatorAndValues: "=da91bf3df3dc",
						},
					},
				},
			},
		},
		{
			testName: "containerImage filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "containerImage-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "read",
							Filters: []string{"containerImage=tracee:latest"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "containerImage-filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.scope.containerImage=tracee:latest",
							eventName:         "read",
							eventFilter:       "read.scope.containerImage",
							operatorAndValues: "=tracee:latest",
						},
					},
				},
			},
		},
		{
			testName: "containerName filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "containerName-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "read",
							Filters: []string{"containerName=tracee"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "containerName-filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.scope.containerName=tracee",
							eventName:         "read",
							eventFilter:       "read.scope.containerName",
							operatorAndValues: "=tracee",
						},
					},
				},
			},
		},
		{
			testName: "podName filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "podName-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "read",
							Filters: []string{"podName=daemonset/tracee"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "podName-filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.scope.podName=daemonset/tracee",
							eventName:         "read",
							eventFilter:       "read.scope.podName",
							operatorAndValues: "=daemonset/tracee",
						},
					},
				},
			},
		},
		{
			testName: "podNamespace filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "podNamespace-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "read",
							Filters: []string{"podNamespace=production"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "podNamespace-filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.scope.podNamespace=production",
							eventName:         "read",
							eventFilter:       "read.scope.podNamespace",
							operatorAndValues: "=production",
						},
					},
				},
			},
		},
		{
			testName: "podUid filter",
			policy: v1beta1.PolicyFile{
				Metadata: v1beta1.Metadata{
					Name: "podUid-filter",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event:   "read",
							Filters: []string{"podUid=poduid"},
						},
					},
				},
			},
			expPolicyScopeMap: PolicyScopeMap{},
			expPolicyEventMap: PolicyEventMap{
				0: {
					policyName: "podUid-filter",
					eventFlags: []eventFlag{
						readEvtFlag,
						{
							full:              "read.scope.podUid=poduid",
							eventName:         "read",
							eventFilter:       "read.scope.podUid",
							operatorAndValues: "=poduid",
						},
					},
				},
			},
		},
		// TODO: does syscall filter make sense for policy?
	}

	for _, test := range tests {
		test := test

		t.Run(test.testName, func(t *testing.T) {
			t.Parallel()

			policyScopeMap, policyEventMap, err := PrepareFilterMapsFromPolicies([]k8s.PolicyInterface{test.policy})
			assert.NoError(t, err)

			for k, v := range test.expPolicyScopeMap {
				ps, ok := policyScopeMap[k]
				assert.True(t, ok)
				assert.Equal(t, v.policyName, ps.policyName)
				require.Equal(t, len(v.scopeFlags), len(ps.scopeFlags))
				for i, sf := range v.scopeFlags {
					assert.Equal(t, sf.full, ps.scopeFlags[i].full)
					assert.Equal(t, sf.scopeName, ps.scopeFlags[i].scopeName)
					assert.Equal(t, sf.operator, ps.scopeFlags[i].operator)
					assert.Equal(t, sf.values, ps.scopeFlags[i].values)
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
	t.Parallel()

	testCases := []struct {
		testName        string
		scopeFlags      []string
		evtFlags        []string
		expectEvtErr    error
		expectScopeErr  error
		expectPolicyErr error
	}{
		{
			testName:        "invalid datafilter 1",
			evtFlags:        []string{"open.data"},
			expectPolicyErr: filters.InvalidEventField(""),
		},
		{
			testName:        "invalid datafilter 2",
			evtFlags:        []string{"open.data.bla=5"},
			expectPolicyErr: filters.InvalidEventField("bla"),
		},
		{
			testName:        "invalid datafilter 3",
			evtFlags:        []string{"open.bla=5"},
			expectPolicyErr: InvalidFilterFlagFormat("open.bla=5"),
		},
		// keep a single args (deprecated) filter test that shall break on future removal
		{
			testName:        "invalid argsfilter 1",
			evtFlags:        []string{"open.args.bla=5"},
			expectPolicyErr: filters.InvalidEventField("bla"),
		},
		{
			testName:        "invalid scope filter 1",
			evtFlags:        []string{"open.scope"},
			expectPolicyErr: filters.InvalidScopeField(""),
		},
		{
			testName:        "invalid scope filter 2",
			evtFlags:        []string{"bla.scope.processName=ls"},
			expectPolicyErr: InvalidEventError("bla"),
		},
		{
			testName:        "invalid scope filter 3",
			evtFlags:        []string{"openat.scope.procName=ls"},
			expectPolicyErr: filters.InvalidScopeField("procName"),
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
		// 	testName:   "success - executable=host:/usr/bin/ls",
		// 	scopeFlags: []string{"executable=host:/usr/bin/ls"},
		// },
		{
			testName:   "success - executable=/usr/bin/ls",
			scopeFlags: []string{"executable=/usr/bin/ls"},
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
			evtFlags: []string{"openat.data.pathname=/bin/ls,/tmp/tracee", "openat.data.pathname!=/etc/passwd"},
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
			evtFlags: []string{"open.retval=5", "security_file_open.data.pathname=/etc/shadow"},
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
		tc := tc

		t.Run(tc.testName, func(t *testing.T) {
			t.Parallel()

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

func TestCreateSinglePolicy(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		policyIdx  int
		scope      policyScopes
		events     policyEvents
		newBinary  bool
		wantPolicy func() *policy.Policy
		wantErr    error
	}{
		{
			name:      "basic policy",
			policyIdx: 1,
			scope: policyScopes{
				policyName: "test-policy",
				scopeFlags: []scopeFlag{{
					full:              "comm=bash",
					scopeName:         "comm",
					operator:          "=",
					operatorAndValues: "=bash",
				}},
			},
			events: policyEvents{
				policyName: "test-policy",
				eventFlags: []eventFlag{{
					full:      "write",
					eventName: "write",
				}},
			},
			wantPolicy: func() *policy.Policy {
				p := policy.NewPolicy()
				p.ID = 1
				p.Name = "test-policy"
				p.CommFilter = filters.NewStringFilter(nil)
				_ = p.CommFilter.Parse("=bash")
				p.Rules[events.Write] = policy.RuleData{
					EventID:     events.Write,
					ScopeFilter: filters.NewScopeFilter(),
					DataFilter:  filters.NewDataFilter(),
					RetFilter:   filters.NewIntFilter(),
				}
				return p
			},
		},
		{
			name:      "multiple filters",
			policyIdx: 2,
			scope: policyScopes{
				policyName: "multi-filter",
				scopeFlags: []scopeFlag{
					{
						full:              "uid=1000",
						scopeName:         "uid",
						operator:          "=",
						operatorAndValues: "=1000",
					},
					{
						full:      "container",
						scopeName: "container",
					},
				},
			},
			events: policyEvents{
				policyName: "multi-filter",
				eventFlags: []eventFlag{
					{
						full:      "open",
						eventName: "open",
					},
					{
						full:              "write.retval=0",
						eventName:         "write",
						eventOptionType:   "retval",
						operatorAndValues: "=0",
					},
				},
			},
			wantPolicy: func() *policy.Policy {
				p := policy.NewPolicy()
				p.ID = 2
				p.Name = "multi-filter"
				p.UIDFilter = filters.NewUInt32Filter()
				_ = p.UIDFilter.Parse("=1000")
				p.ContFilter = filters.NewBoolFilter()
				_ = p.ContFilter.Parse("container")

				p.Rules[events.Open] = policy.RuleData{
					EventID:     events.Open,
					ScopeFilter: filters.NewScopeFilter(),
					DataFilter:  filters.NewDataFilter(),
					RetFilter:   filters.NewIntFilter(),
				}
				p.Rules[events.Write] = policy.RuleData{
					EventID:     events.Write,
					ScopeFilter: filters.NewScopeFilter(),
					DataFilter:  filters.NewDataFilter(),
					RetFilter:   filters.NewIntFilter(),
				}
				_ = p.Rules[events.Write].RetFilter.Parse("=0")
				return p
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := createSinglePolicy(tc.policyIdx, tc.scope, tc.events, tc.newBinary)

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.Equal(t, tc.wantErr.Error(), err.Error())
				return
			}

			require.NoError(t, err)
			want := tc.wantPolicy()
			assert.Equal(t, want, got)
		})
	}
}

func TestParseScopeFilters(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		policy     *policy.Policy
		scopeFlags []scopeFlag
		newBinary  bool
		wantErr    error
		validate   func(*testing.T, *policy.Policy)
	}{
		{
			name:   "single comm filter",
			policy: policy.NewPolicy(),
			scopeFlags: []scopeFlag{{
				full:              "comm=bash",
				scopeName:         "comm",
				operator:          "=",
				operatorAndValues: "=bash",
			}},
			validate: func(t *testing.T, p *policy.Policy) {
				assert.NotNil(t, p.CommFilter)
			},
		},
		{
			name:   "container filter variations",
			policy: policy.NewPolicy(),
			scopeFlags: []scopeFlag{
				{
					full:      "container",
					scopeName: "container",
				},
				{
					full:              "container=new",
					scopeName:         "container",
					operator:          "=",
					operatorAndValues: "=new",
				},
			},
			validate: func(t *testing.T, p *policy.Policy) {
				assert.NotNil(t, p.ContFilter)
				assert.NotNil(t, p.NewContFilter)
			},
		},
		{
			name:   "invalid scope filter",
			policy: policy.NewPolicy(),
			scopeFlags: []scopeFlag{{
				full:              "invalid=value",
				scopeName:         "invalid",
				operator:          "=",
				operatorAndValues: "=value",
			}},
			wantErr: InvalidScopeOptionError("invalid=value", false),
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := parseScopeFilters(tc.policy, tc.scopeFlags, tc.newBinary)

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.Equal(t, tc.wantErr.Error(), err.Error())
				return
			}

			require.NoError(t, err)
			if tc.validate != nil {
				tc.validate(t, tc.policy)
			}
		})
	}
}

func TestParseEventFilters(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		policy     *policy.Policy
		eventFlags []eventFlag
		wantErr    error
		validate   func(*testing.T, *policy.Policy)
	}{
		{
			name:   "basic event",
			policy: policy.NewPolicy(),
			eventFlags: []eventFlag{{
				full:      "write",
				eventName: "write",
			}},
			validate: func(t *testing.T, p *policy.Policy) {
				assert.Contains(t, p.Rules, events.Write)
			},
		},
		{
			name:   "event with retval filter",
			policy: policy.NewPolicy(),
			eventFlags: []eventFlag{{
				full:              "write.retval=0",
				eventName:         "write",
				eventOptionType:   "retval",
				operatorAndValues: "=0",
			}},
			validate: func(t *testing.T, p *policy.Policy) {
				assert.Contains(t, p.Rules, events.Write)
				assert.NotNil(t, p.Rules[events.Write].RetFilter)
			},
		},
		{
			name:   "event with data filter",
			policy: policy.NewPolicy(),
			eventFlags: []eventFlag{{
				full:              "openat.data.pathname=/etc/passwd",
				eventName:         "openat",
				eventOptionType:   "data",
				eventOptionName:   "pathname",
				operatorAndValues: "=/etc/passwd",
			}},
			validate: func(t *testing.T, p *policy.Policy) {
				assert.Contains(t, p.Rules, events.Openat)
				assert.NotNil(t, p.Rules[events.Openat].DataFilter)
			},
		},
		{
			name:   "wildcard event",
			policy: policy.NewPolicy(),
			eventFlags: []eventFlag{{
				full:      "sched_process_*",
				eventName: "sched_process_*",
			}},
			validate: func(t *testing.T, p *policy.Policy) {
				// Check that all sched_process events are included
				assert.Contains(t, p.Rules, events.SchedProcessExec)
				assert.Contains(t, p.Rules, events.SchedProcessFork)
				assert.Contains(t, p.Rules, events.SchedProcessExit)
			},
		},
		{
			name:   "wildcard event with filter",
			policy: policy.NewPolicy(),
			eventFlags: []eventFlag{{
				full:      "sched_process_*",
				eventName: "sched_process_*",
			}, {
				full:              "sched_process_exec.retval=0",
				eventName:         "sched_process_exec",
				eventOptionType:   "retval",
				operatorAndValues: "=0",
			}},
			validate: func(t *testing.T, p *policy.Policy) {
				assert.Contains(t, p.Rules, events.SchedProcessExec)
				assert.Contains(t, p.Rules, events.SchedProcessFork)
				assert.Contains(t, p.Rules, events.SchedProcessExit)
				// Check that retval filter is applied only to sched_process_exec event
				assert.NotNil(t, p.Rules[events.SchedProcessExec].RetFilter)
				assert.NotNil(t, p.Rules[events.SchedProcessFork].RetFilter)
				assert.NotNil(t, p.Rules[events.SchedProcessExit].RetFilter)
			},
		},
		{
			name:   "non-existing event",
			policy: policy.NewPolicy(),
			eventFlags: []eventFlag{{
				full:      "nonexistent",
				eventName: "nonexistent",
			}},
			wantErr: InvalidEventError("nonexistent"),
		},
		{
			name:   "non-existing event expansion",
			policy: policy.NewPolicy(),
			eventFlags: []eventFlag{{
				full:      "nonexistent*",
				eventName: "nonexistent*",
			}},
			wantErr: InvalidEventError("nonexistent*"),
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := parseEventFilters(tc.policy, tc.eventFlags)

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.Equal(t, tc.wantErr.Error(), err.Error())
				return
			}

			require.NoError(t, err)
			if tc.validate != nil {
				tc.validate(t, tc.policy)
			}
		})
	}
}
