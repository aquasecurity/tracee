package policy

import (
	"errors"
	"testing"

	"gotest.tools/assert"
)

func TestPolicyValidate(t *testing.T) {
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
			expectedError: errors.New("policy.validateEvent: policy empty_event_name, event cannot be empty"),
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
			expectedError: errors.New("policy.validateEvent: policy invalid_event_name, event non_existing_event is not valid"),
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
			expectedError: errors.New("policy.parseScope: policy invalid_scope_operator, scope random is not valid"),
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
			expectedError: errors.New("policy.PolicyFile.validateScope: policy invalid_scope, scope random is not valid"),
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
			expectedError: errors.New("policy.PolicyFile.validateRules: policy invalid_filter_operator, invalid filter operator: random"),
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
			expectedError: errors.New("policy.PolicyFile.Validate: policy empty_policy_action, default action cannot be empty"),
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
			expectedError: errors.New("policy.validateAction: policy invalid_policy_action, action audit is not valid"),
		},
		// invalid args?
		// invalid retval?
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			err := test.policy.Validate()
			if test.expectedError != nil {
				assert.ErrorContains(t, err, test.expectedError.Error())
			}
		})
	}
}
