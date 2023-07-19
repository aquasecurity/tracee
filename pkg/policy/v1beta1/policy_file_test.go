package v1beta1

import (
	"errors"
	"testing"

	"gotest.tools/assert"

	"github.com/aquasecurity/tracee/pkg/events"
)

func TestPolicyValidate(t *testing.T) {
	fakeSignatureEvent := events.NewEventDefinition("fake_signature", []string{"signatures", "default"}, nil)

	err := events.Definitions.Add(9000, fakeSignatureEvent)
	assert.NilError(t, err)

	tests := []struct {
		testName            string
		policy              PolicyFile
		expectedError       error
		expectedPolicyError bool
	}{
		{
			testName: "empty name",
			policy: PolicyFile{
				Metadata: Metadata{Name: ""},
			},
			expectedError: errors.New("policy name cannot be empty"),
		},
		{
			testName: "empty API",
			policy: PolicyFile{
				APIVersion: "",
				Metadata:   Metadata{Name: "emptyAPI"},
			},
			expectedError: errors.New("policy emptyAPI, apiVersion not supported"),
		},
		{
			testName: "invalid API",
			policy: PolicyFile{
				APIVersion: "aquasecurity.github.io/test",
				Metadata:   Metadata{Name: "invalidAPI"},
			},
			expectedError: errors.New("policy invalidAPI, apiVersion not supported"),
		},
		{
			testName: "empty Kind",
			policy: PolicyFile{
				APIVersion: "aquasecurity.github.io/v1beta1",
				Metadata:   Metadata{Name: "emptyKind"},
			},
			expectedError: errors.New("policy emptyKind, kind not supported"),
		},
		{
			testName: "invalid Kind",
			policy: PolicyFile{
				APIVersion: "aquasecurity.github.io/v1beta1",
				Kind:       "Policy",
				Metadata:   Metadata{Name: "invalidKind"},
			},
			expectedError: errors.New("policy invalidKind, kind not supported"),
		},
		{
			testName: "empty scope",
			policy: PolicyFile{
				APIVersion: "aquasecurity.github.io/v1beta1",
				Kind:       "TraceePolicy",
				Metadata: Metadata{
					Name: "empty_scope",
				},
				Spec: PolicySpec{
					Scope:          []string{},
					DefaultActions: []string{"log"},
				},
			},
			expectedError: errors.New("policy empty_scope, scope cannot be empty"),
		},
		{
			testName: "empty rules",
			policy: PolicyFile{
				APIVersion: "aquasecurity.github.io/v1beta1",
				Kind:       "TraceePolicy",
				Metadata: Metadata{
					Name: "empty_rules",
				},
				Spec: PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules:          []Rule{},
				},
			},
			expectedError: errors.New("policy empty_rules, rules cannot be empty"),
		},
		{
			testName: "empty event name",
			policy: PolicyFile{
				APIVersion: "aquasecurity.github.io/v1beta1",
				Kind:       "TraceePolicy",
				Metadata: Metadata{
					Name: "empty_event_name",
				},
				Spec: PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []Rule{
						{Event: ""},
					},
				},
			},
			expectedError: errors.New("v1beta1.validateEvent: policy empty_event_name, event cannot be empty"),
		},
		{
			testName: "invalid event name",
			policy: PolicyFile{
				APIVersion: "aquasecurity.github.io/v1beta1",
				Kind:       "TraceePolicy",
				Metadata: Metadata{
					Name: "invalid_event_name",
				},
				Spec: PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []Rule{
						{Event: "non_existing_event"},
					},
				},
			},
			expectedError: errors.New("v1beta1.validateEvent: policy invalid_event_name, event non_existing_event is not valid"),
		},
		{
			testName: "invalid_scope_operator",
			policy: PolicyFile{
				APIVersion: "aquasecurity.github.io/v1beta1",
				Kind:       "TraceePolicy",
				Metadata: Metadata{
					Name: "invalid_scope_operator",
				},
				Spec: PolicySpec{
					Scope:          []string{"random"},
					DefaultActions: []string{"log"},
					Rules: []Rule{
						{Event: "write"},
					},
				},
			},
			expectedError: errors.New("v1beta1.parseScope: policy invalid_scope_operator, scope random is not valid"),
		},
		{
			testName: "invalid_scope",
			policy: PolicyFile{
				APIVersion: "aquasecurity.github.io/v1beta1",
				Kind:       "TraceePolicy",
				Metadata: Metadata{
					Name: "invalid_scope",
				},
				Spec: PolicySpec{
					Scope:          []string{"random!=0"},
					DefaultActions: []string{"log"},
					Rules: []Rule{
						{Event: "write"},
					},
				},
			},
			expectedError: errors.New("v1beta1.PolicyFile.validateScope: policy invalid_scope, scope random is not valid"),
		},
		{
			testName: "global scope must be unique",
			policy: PolicyFile{
				APIVersion: "aquasecurity.github.io/v1beta1",
				Kind:       "TraceePolicy",
				Metadata: Metadata{
					Name: "global_scope_must_be_unique",
				},
				Spec: PolicySpec{
					Scope:          []string{"global", "uid=1000"},
					DefaultActions: []string{"log"},
					Rules: []Rule{
						{Event: "write"},
					},
				},
			},
			expectedError: errors.New("policy global_scope_must_be_unique, global scope must be unique"),
		},
		{
			testName: "duplicated event",
			policy: PolicyFile{
				APIVersion: "aquasecurity.github.io/v1beta1",
				Kind:       "TraceePolicy",
				Metadata: Metadata{
					Name: "duplicated_event",
				},
				Spec: PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
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
			policy: PolicyFile{
				APIVersion: "aquasecurity.github.io/v1beta1",
				Kind:       "TraceePolicy",
				Metadata: Metadata{
					Name: "invalid_filter_operator",
				},
				Spec: PolicySpec{
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
			},
			expectedError: errors.New("v1beta1.PolicyFile.validateRules: policy invalid_filter_operator, invalid filter operator: random"),
		},
		{
			testName: "invalid policy action",
			policy: PolicyFile{
				APIVersion: "aquasecurity.github.io/v1beta1",
				Kind:       "TraceePolicy",
				Metadata: Metadata{
					Name: "invalid_policy_action",
				},
				Spec: PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"audit"},
					Rules: []Rule{
						{Event: "write"},
					},
				},
			},
			expectedError: errors.New("v1beta1.validateActions: policy invalid_policy_action, action audit is not valid"),
		},
		{
			testName: "invalid retval",
			policy: PolicyFile{
				APIVersion: "aquasecurity.github.io/v1beta1",
				Kind:       "TraceePolicy",
				Metadata: Metadata{
					Name: "invalid_retval",
				},
				Spec: PolicySpec{
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
			},
			expectedError: errors.New("v1beta1.PolicyFile.validateRules: policy invalid_retval, invalid filter operator: retval"),
		},
		{
			testName: "empty retval",
			policy: PolicyFile{
				APIVersion: "aquasecurity.github.io/v1beta1",
				Kind:       "TraceePolicy",
				Metadata: Metadata{
					Name: "empty_retval",
				},
				Spec: PolicySpec{
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
			},
			expectedError: errors.New("v1beta1.PolicyFile.validateRules: policy empty_retval, retval cannot be empty"),
		},
		{
			testName: "retval not an integer",
			policy: PolicyFile{
				APIVersion: "aquasecurity.github.io/v1beta1",
				Kind:       "TraceePolicy",
				Metadata: Metadata{
					Name: "retval_not_an_integer",
				},
				Spec: PolicySpec{
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
			},
			expectedError: errors.New("v1beta1.PolicyFile.validateRules: policy retval_not_an_integer, retval must be an integer: lala"),
		},
		{
			testName: "empty arg name 1",
			policy: PolicyFile{
				APIVersion: "aquasecurity.github.io/v1beta1",
				Kind:       "TraceePolicy",
				Metadata: Metadata{
					Name: "empty_filter_arg_1",
				},
				Spec: PolicySpec{
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
			},
			expectedError: errors.New("v1beta1.PolicyFile.validateRules: policy empty_filter_arg_1, invalid filter operator: args"),
		},
		{
			testName: "empty arg name 3",
			policy: PolicyFile{
				APIVersion: "aquasecurity.github.io/v1beta1",
				Kind:       "TraceePolicy",
				Metadata: Metadata{
					Name: "empty_filter_arg_3",
				},
				Spec: PolicySpec{
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
			},
			expectedError: errors.New("v1beta1.PolicyFile.validateRules: policy empty_filter_arg_3, arg name can't be empty"),
		},
		{
			testName: "empty arg name 4",
			policy: PolicyFile{
				APIVersion: "aquasecurity.github.io/v1beta1",
				Kind:       "TraceePolicy",
				Metadata: Metadata{
					Name: "empty_filter_arg_4",
				},
				Spec: PolicySpec{
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
			},
			expectedError: errors.New("v1beta1.PolicyFile.validateRules: policy empty_filter_arg_4, arg name can't be empty"),
		},
		{
			testName: "invalid arg",
			policy: PolicyFile{
				APIVersion: "aquasecurity.github.io/v1beta1",
				Kind:       "TraceePolicy",
				Metadata: Metadata{
					Name: "invalid_arg",
				},
				Spec: PolicySpec{
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
			},
			expectedError: errors.New("v1beta1.validateEventArg: policy invalid_arg, event openat does not have argument lala"),
		},
		{
			testName: "empty arg value",
			policy: PolicyFile{
				APIVersion: "aquasecurity.github.io/v1beta1",
				Kind:       "TraceePolicy",
				Metadata: Metadata{
					Name: "empty_arg_value",
				},
				Spec: PolicySpec{
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
			},
			expectedError: errors.New("v1beta1.validateEventArg: policy empty_arg_value, arg pathname value can't be empty"),
		},
		{
			testName: "empty arg value",
			policy: PolicyFile{
				APIVersion: "aquasecurity.github.io/v1beta1",
				Kind:       "TraceePolicy",
				Metadata: Metadata{
					Name: "empty_arg_value",
				},
				Spec: PolicySpec{
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
			},
			expectedError: errors.New("v1beta1.validateEventArg: policy empty_arg_value, arg pathname value can't be empty"),
		},
		{
			testName: "signature filter arg",
			policy: PolicyFile{
				APIVersion: "aquasecurity.github.io/v1beta1",
				Kind:       "TraceePolicy",
				Metadata: Metadata{
					Name: "signature_filter_arg",
				},
				Spec: PolicySpec{
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
