package v1beta1

import (
	"errors"
	"testing"

	"gotest.tools/assert"

	"github.com/aquasecurity/tracee/pkg/events"
	k8s "github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
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
		nil,
	)

	err := events.Core.Add(events.StartSignatureID, fakeSigEventDefinition)
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
				Spec: k8s.PolicySpec{
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
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules:          []k8s.Rule{},
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
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
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
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
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
				Spec: k8s.PolicySpec{
					Scope:          []string{"random"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
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
				Spec: k8s.PolicySpec{
					Scope:          []string{"random!=0"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
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
				Spec: k8s.PolicySpec{
					Scope:          []string{"global", "uid=1000"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
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
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
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
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
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
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"audit"},
					Rules: []k8s.Rule{
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
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
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
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
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
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
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
			testName: "empty data name 1",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "empty-filter-data-1",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event: "write",
							Filters: []string{
								"data",
							},
						},
					},
				},
			},
			expectedError: errors.New("v1beta1.PolicyFile.validateRules: policy empty-filter-data-1, invalid filter operator: data"),
		},
		{
			testName: "empty data name 3",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "empty-filter-data-3",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event: "write",
							Filters: []string{
								"data=",
							},
						},
					},
				},
			},
			expectedError: errors.New("v1beta1.PolicyFile.validateRules: policy empty-filter-data-3, data name can't be empty"),
		},
		{
			testName: "empty data name 4",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "empty-filter-data-4",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event: "write",
							Filters: []string{
								"data=lala",
							},
						},
					},
				},
			},
			expectedError: errors.New("v1beta1.PolicyFile.validateRules: policy empty-filter-data-4, data name can't be empty"),
		},
		{
			testName: "invalid data",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "invalid-data",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event: "openat",
							Filters: []string{
								"data.lala=1",
							},
						},
					},
				},
			},
			expectedError: errors.New("v1beta1.validateEventData: policy invalid-data, event openat does not have data lala"),
		},
		// keep a single args (deprecated) filter test that shall break on future removal
		{
			testName: "invalid args",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "invalid-args",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event: "openat",
							Filters: []string{
								"data.lala=1",
							},
						},
					},
				},
			},
			expectedError: errors.New("v1beta1.validateEventData: policy invalid-args, event openat does not have data lala"),
		},
		{
			testName: "empty data value",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "empty-data-value",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event: "openat",
							Filters: []string{
								"data.pathname=",
							},
						},
					},
				},
			},
			expectedError: errors.New("v1beta1.validateEventData: policy empty-data-value, data pathname value can't be empty"),
		},
		{
			testName: "empty data value",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "empty-data-value",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event: "openat",
							Filters: []string{
								"data.pathname!=",
							},
						},
					},
				},
			},
			expectedError: errors.New("v1beta1.validateEventData: policy empty-data-value, data pathname value can't be empty"),
		},
		// deprecated this test after deprecated args option
		{
			testName: "empty args value",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "empty-args-value",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event: "openat",
							Filters: []string{
								"args.pathname!=",
							},
						},
					},
				},
			},
			expectedError: errors.New("v1beta1.validateEventData: policy empty-args-value, data pathname value can't be empty"),
		},
		{
			testName: "signature filter data",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "signature-filter-data",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event: "fake_signature",
							Filters: []string{
								"data.lala=lala",
								"data.lele!=lele",
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
