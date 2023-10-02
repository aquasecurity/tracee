package v1beta1

import (
	"errors"
	"testing"

	"gotest.tools/assert"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestPolicyValidate(t *testing.T) {
	t.Parallel()

	fakeSigEventDefinition := events.NewDefinition(
		0,
		events.Sys32Undefined,
		"fake_signature",
		events.NewVersion(1, 0, 0), // Version
		"fake_description",
		"",
		false,
		false,
		[]string{"signatures", "default"},
		events.NewDependencies(
			[]events.ID{},
			[]events.KSymbol{},
			[]events.Probe{},
			[]events.TailCall{},
			events.Capabilities{},
		),
		[]trace.ArgMeta{},
	)

	err := events.Core.Add(9000, fakeSigEventDefinition)
	assert.NilError(t, err)

	tests := []struct {
		testName            string
		policy              PolicyFile
		expectedError       error
		expectedPolicyError bool
	}{
		{
			testName: "empty API",
			policy: PolicyFile{
				APIVersion: "",
				Metadata:   Metadata{Name: "empty-api"},
			},
			expectedError: errors.New("policy empty-api, apiVersion not supported"),
		},
		{
			testName: "invalid API",
			policy: PolicyFile{
				APIVersion: "aquasecurity.github.io/test",
				Metadata:   Metadata{Name: "invalid-api"},
			},
			expectedError: errors.New("policy invalid-api, apiVersion not supported"),
		},
		{
			testName: "empty Kind",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Metadata:   Metadata{Name: "empty-kind"},
			},
			expectedError: errors.New("policy empty-kind, kind not supported"),
		},
		{
			testName: "invalid Kind",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policies",
				Metadata:   Metadata{Name: "invalid-kind"},
			},
			expectedError: errors.New("policy invalid-kind, kind not supported"),
		},
		{
			testName: "empty scope",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "empty-scope",
				},
				Spec: PolicySpec{
					Scope:          []string{},
					DefaultActions: []string{"log"},
				},
			},
			expectedError: errors.New("policy empty-scope, scope cannot be empty"),
		},
		{
			testName: "empty rules",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "empty-rules",
				},
				Spec: PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules:          []Rule{},
				},
			},
			expectedError: errors.New("policy empty-rules, rules cannot be empty"),
		},
		{
			testName: "empty event name",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "empty-event-name",
				},
				Spec: PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []Rule{
						{Event: ""},
					},
				},
			},
			expectedError: errors.New("v1beta1.validateEvent: policy empty-event-name, event cannot be empty"),
		},
		{
			testName: "invalid event name",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "invalid-event-name",
				},
				Spec: PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []Rule{
						{Event: "non_existing_event"},
					},
				},
			},
			expectedError: errors.New("v1beta1.validateEvent: policy invalid-event-name, event non_existing_event is not valid"),
		},
		{
			testName: "invalid_scope_operator",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "invalid-scope-operator",
				},
				Spec: PolicySpec{
					Scope:          []string{"random"},
					DefaultActions: []string{"log"},
					Rules: []Rule{
						{Event: "write"},
					},
				},
			},
			expectedError: errors.New("v1beta1.parseScope: policy invalid-scope-operator, scope random is not valid"),
		},
		{
			testName: "invalid_scope",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "invalid-scope",
				},
				Spec: PolicySpec{
					Scope:          []string{"random!=0"},
					DefaultActions: []string{"log"},
					Rules: []Rule{
						{Event: "write"},
					},
				},
			},
			expectedError: errors.New("v1beta1.PolicyFile.validateScope: policy invalid-scope, scope random is not valid"),
		},
		{
			testName: "global scope must be unique",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "global-scope-must-be-unique",
				},
				Spec: PolicySpec{
					Scope:          []string{"global", "uid=1000"},
					DefaultActions: []string{"log"},
					Rules: []Rule{
						{Event: "write"},
					},
				},
			},
			expectedError: errors.New("policy global-scope-must-be-unique, global scope must be unique"),
		},
		{
			testName: "duplicated event",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "duplicated-event",
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
			expectedError: errors.New("policy duplicated-event, event write is duplicated"),
		},
		{
			testName: "invalid filter operator",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "invalid-filter-operator",
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
			expectedError: errors.New("v1beta1.PolicyFile.validateRules: policy invalid-filter-operator, invalid filter operator: random"),
		},
		{
			testName: "invalid policy action",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "invalid-policy-action",
				},
				Spec: PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"audit"},
					Rules: []Rule{
						{Event: "write"},
					},
				},
			},
			expectedError: errors.New("v1beta1.validateActions: policy invalid-policy-action, action audit is not valid"),
		},
		{
			testName: "invalid retval",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "invalid-retval",
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
			expectedError: errors.New("v1beta1.PolicyFile.validateRules: policy invalid-retval, invalid filter operator: retval"),
		},
		{
			testName: "empty retval",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "empty-retval",
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
			expectedError: errors.New("v1beta1.PolicyFile.validateRules: policy empty-retval, retval cannot be empty"),
		},
		{
			testName: "retval not an integer",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "retval-not-an-integer",
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
			expectedError: errors.New("v1beta1.PolicyFile.validateRules: policy retval-not-an-integer, retval must be an integer: lala"),
		},
		{
			testName: "empty arg name 1",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "empty-filter-arg-1",
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
			expectedError: errors.New("v1beta1.PolicyFile.validateRules: policy empty-filter-arg-1, invalid filter operator: args"),
		},
		{
			testName: "empty arg name 3",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "empty-filter-arg-3",
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
			expectedError: errors.New("v1beta1.PolicyFile.validateRules: policy empty-filter-arg-3, arg name can't be empty"),
		},
		{
			testName: "empty arg name 4",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "empty-filter-arg-4",
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
			expectedError: errors.New("v1beta1.PolicyFile.validateRules: policy empty-filter-arg-4, arg name can't be empty"),
		},
		{
			testName: "invalid arg",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "invalid-arg",
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
			expectedError: errors.New("v1beta1.validateEventArg: policy invalid-arg, event openat does not have argument lala"),
		},
		{
			testName: "empty arg value",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "empty-arg-value",
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
			expectedError: errors.New("v1beta1.validateEventArg: policy empty-arg-value, arg pathname value can't be empty"),
		},
		{
			testName: "empty arg value",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "empty-arg-value",
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
			expectedError: errors.New("v1beta1.validateEventArg: policy empty-arg-value, arg pathname value can't be empty"),
		},
		{
			testName: "signature filter arg",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "signature-filter-arg",
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
		test := test

		t.Run(test.testName, func(t *testing.T) {
			t.Parallel()

			err := test.policy.Validate()
			if test.expectedError != nil {
				assert.ErrorContains(t, err, test.expectedError.Error())
			} else {
				assert.NilError(t, err)
			}
		})
	}
}
