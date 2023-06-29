package policy

import (
	"errors"
	"testing"

	"gotest.tools/assert"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestPolicyValidate(t *testing.T) {
	fakeSignatureEvent := events.NewEvent(
		events.ID(0),                      // id
		events.Sys32Undefined,             // id32
		"fake_signature",                  // eventName
		"",                                // docPath
		false,                             // internal
		false,                             // syscall
		[]string{"signatures", "default"}, // sets
		events.NewDependencies(
			[]events.ID{}, // ids
			nil,           // probes
			nil,           // ksyms
			nil,           // tailcalls
			nil,           // capabilities
		),
		[]trace.ArgMeta{},
	)

	err := events.Core.Add(9000, fakeSignatureEvent)
	assert.NilError(t, err)

	tests := []struct {
		testName            string
		policy              PolicyFile
		expectedError       error
		expectedPolicyError bool
	}{
		{
			testName:      "empty name",
			policy:        PolicyFile{Name: ""},
			expectedError: errors.New("policy name cannot be empty"),
		},
		{
			testName: "empty description",
			policy: PolicyFile{
				Name:        "empty_description",
				Description: "",
			},
			expectedError: errors.New("policy.PolicyFile.Validate: policy empty_description, description cannot be empty"),
		},
		{
			testName: "empty scope",
			policy: PolicyFile{
				Name:           "empty_scope",
				Description:    "empty scope",
				Scope:          []string{},
				DefaultActions: []string{"log"},
			},
			expectedError: errors.New("policy empty_scope, scope cannot be empty"),
		},
		{
			testName: "empty rules",
			policy: PolicyFile{
				Name:           "empty_rules",
				Description:    "empty rules",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules:          []Rule{},
			},
			expectedError: errors.New("policy empty_rules, rules cannot be empty"),
		},
		{
			testName: "empty event name",
			policy: PolicyFile{
				Name:           "empty_event_name",
				Description:    "empty event name",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []Rule{
					{Event: ""},
				},
			},
			expectedError: errors.New("policy.validateEvent: policy empty_event_name, event cannot be empty"),
		},
		{
			testName: "invalid event name",
			policy: PolicyFile{
				Name:           "invalid_event_name",
				Description:    "invalid event name",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []Rule{
					{Event: "non_existing_event"},
				},
			},
			expectedError: errors.New("policy.validateEvent: policy invalid_event_name, event non_existing_event is not valid"),
		},
		{
			testName: "invalid_scope_operator",
			policy: PolicyFile{
				Name:           "invalid_scope_operator",
				Description:    "invalid scope operator",
				Scope:          []string{"random"},
				DefaultActions: []string{"log"},
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expectedError: errors.New("policy.parseScope: policy invalid_scope_operator, scope random is not valid"),
		},
		{
			testName: "invalid_scope",
			policy: PolicyFile{
				Name:           "invalid_scope",
				Description:    "invalid scope",
				Scope:          []string{"random!=0"},
				DefaultActions: []string{"log"},
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expectedError: errors.New("policy.PolicyFile.validateScope: policy invalid_scope, scope random is not valid"),
		},
		{
			testName: "global scope must be unique",
			policy: PolicyFile{
				Name:           "global_scope_must_be_unique",
				Description:    "global scope must be unique",
				Scope:          []string{"global", "uid=1000"},
				DefaultActions: []string{"log"},
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expectedError: errors.New("policy global_scope_must_be_unique, global scope must be unique"),
		},
		{
			testName: "duplicated event",
			policy: PolicyFile{
				Name:           "duplicated_event",
				Description:    "duplicated event",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
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
				Name:           "invalid_filter_operator",
				Description:    "invalid filter operator",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []Rule{
					{
						Event: "write",
						Filters: []string{
							"random",
						},
					},
				},
			},
			expectedError: errors.New("policy.PolicyFile.validateRules: policy invalid_filter_operator, invalid filter operator: random"),
		},
		{
			testName: "invalid filter",
			policy: PolicyFile{
				Name:           "invalid_filter",
				Description:    "invalid filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []Rule{
					{
						Event: "write",
						Filters: []string{
							"random!=0",
						},
					},
				},
			},
			expectedError: errors.New("policy.validateContext: policy invalid_filter, filter random is not valid"),
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
			expectedError: errors.New("policy.PolicyFile.validateDefaultActions: policy empty_policy_action, default actions cannot be empty"),
		},
		{
			testName: "invalid policy action",
			policy: PolicyFile{
				Name:           "invalid_policy_action",
				Description:    "invalid policy action",
				Scope:          []string{"global"},
				DefaultActions: []string{"audit"},
				Rules: []Rule{
					{Event: "write"},
				},
			},
			expectedError: errors.New("policy.validateActions: policy invalid_policy_action, action audit is not valid"),
		},
		{
			testName: "invalid retval",
			policy: PolicyFile{
				Name:           "invalid_retval",
				Description:    "invalid retval filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []Rule{
					{
						Event: "write",
						Filters: []string{
							"retval",
						},
					},
				},
			},
			expectedError: errors.New("policy.PolicyFile.validateRules: policy invalid_retval, invalid filter operator: retval"),
		},
		{
			testName: "empty retval",
			policy: PolicyFile{
				Name:           "empty_retval",
				Description:    "empty retval filter",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []Rule{
					{
						Event: "write",
						Filters: []string{
							"retval=",
						},
					},
				},
			},
			expectedError: errors.New("policy.PolicyFile.validateRules: policy empty_retval, retval cannot be empty"),
		},
		{
			testName: "retval not an integer",
			policy: PolicyFile{
				Name:           "retval_not_an_integer",
				Description:    "retval not an integer",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []Rule{
					{
						Event: "write",
						Filters: []string{
							"retval=lala",
						},
					},
				},
			},
			expectedError: errors.New("policy.PolicyFile.validateRules: policy retval_not_an_integer, retval must be an integer: lala"),
		},
		{
			testName: "empty arg name 1",
			policy: PolicyFile{
				Name:           "empty_filter_arg_1",
				Description:    "empty filter arg 1",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []Rule{
					{
						Event: "write",
						Filters: []string{
							"args",
						},
					},
				},
			},
			expectedError: errors.New("policy.PolicyFile.validateRules: policy empty_filter_arg_1, invalid filter operator: args"),
		},
		{
			testName: "empty arg name 3",
			policy: PolicyFile{
				Name:           "empty_filter_arg_3",
				Description:    "empty filter arg 3",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []Rule{
					{
						Event: "write",
						Filters: []string{
							"args=",
						},
					},
				},
			},
			expectedError: errors.New("policy.PolicyFile.validateRules: policy empty_filter_arg_3, arg name can't be empty"),
		},
		{
			testName: "empty arg name 4",
			policy: PolicyFile{
				Name:           "empty_filter_arg_4",
				Description:    "empty filter arg 4",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []Rule{
					{
						Event: "write",
						Filters: []string{
							"args=lala",
						},
					},
				},
			},
			expectedError: errors.New("policy.PolicyFile.validateRules: policy empty_filter_arg_4, arg name can't be empty"),
		},
		{
			testName: "invalid arg",
			policy: PolicyFile{
				Name:           "invalid_arg",
				Description:    "invalid arg",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []Rule{
					{
						Event: "openat",
						Filters: []string{
							"args.lala=1",
						},
					},
				},
			},
			expectedError: errors.New("policy.validateEventArg: policy invalid_arg, event openat does not have argument lala"),
		},
		{
			testName: "empty arg value",
			policy: PolicyFile{
				Name:           "empty_arg_value",
				Description:    "empty arg value",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []Rule{
					{
						Event: "openat",
						Filters: []string{
							"args.pathname=",
						},
					},
				},
			},
			expectedError: errors.New("policy.validateEventArg: policy empty_arg_value, arg pathname value can't be empty"),
		},
		{
			testName: "empty arg value",
			policy: PolicyFile{
				Name:           "empty_arg_value",
				Description:    "empty arg value",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []Rule{
					{
						Event: "openat",
						Filters: []string{
							"args.pathname!=",
						},
					},
				},
			},
			expectedError: errors.New("policy.validateEventArg: policy empty_arg_value, arg pathname value can't be empty"),
		},
		{
			testName: "signature filter arg",
			policy: PolicyFile{
				Name:           "signature_filter_arg",
				Description:    "signature filter arg",
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules: []Rule{
					{
						Event: "fake_signature",
						Filters: []string{
							"args.lala=lala",
							"args.lele!=lele",
						},
					},
				},
			},
			expectedError: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			err := test.policy.Validate()
			if test.expectedError != nil {
				assert.ErrorContains(t, err, test.expectedError.Error())
			} else {
				assert.NilError(t, err)
			}
		})
	}
}
