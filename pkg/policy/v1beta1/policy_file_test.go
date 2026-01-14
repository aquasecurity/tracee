package v1beta1

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"gotest.tools/assert"

	"github.com/aquasecurity/tracee/pkg/events"
	k8s "github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
)

func TestPolicyValidate(t *testing.T) {
	t.Parallel()

	fakeSigEventDefinition := events.NewDefinition(
		0,
		events.Sys32Undefined,
		"fake_signature",
		events.NewVersion(1, 0, 0), // Version
		"fake_description",
		false,
		false,
		[]string{"signatures", "default"},
		events.NewDependencyStrategy(
			events.NewDependencies(
				[]events.ID{},
				[]events.KSymbol{},
				[]events.Probe{},
				[]events.TailCall{},
				events.Capabilities{},
			)),
		[]events.DataField{},
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
			testName: "sets",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "sets",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event: "signatures",
						},
					},
				},
			},
			expectedError: nil,
		},
		{
			testName: "sets without specific event",
			policy: PolicyFile{
				APIVersion: "tracee.aquasec.com/v1beta1",
				Kind:       "Policy",
				Metadata: Metadata{
					Name: "sets-without-specific-event",
				},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules: []k8s.Rule{
						{
							Event: "signatures,-openat",
						},
					},
				},
			},
			expectedError: nil,
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

func TestPoliciesFromPaths(t *testing.T) {
	t.Parallel()

	// Determine which event to use - reuse fake_signature if it exists, otherwise create a new one
	eventName := "fake_signature"
	_, exists := events.Core.GetDefinitionIDByName("fake_signature")
	if !exists {
		// If it doesn't exist, create it with a different ID and name to avoid conflicts
		eventName = "fake_signature_policies"
		fakeSigEventDefinition := events.NewDefinition(
			0,
			events.Sys32Undefined,
			eventName,
			events.NewVersion(1, 0, 0),
			"fake_description",
			false,
			false,
			[]string{"signatures", "default"},
			events.NewDependencyStrategy(
				events.NewDependencies(
					[]events.ID{},
					[]events.KSymbol{},
					[]events.Probe{},
					[]events.TailCall{},
					events.Capabilities{},
				)),
			[]events.DataField{},
			nil,
		)

		// Use a different ID to avoid conflict with TestPolicyValidate
		err := events.Core.Add(events.StartSignatureID+1, fakeSigEventDefinition)
		assert.NilError(t, err)
	}

	validYAMLPolicy := fmt.Sprintf(`apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: test-yaml-policy
  annotations:
    description: Test YAML policy
spec:
  scope:
    - global
  defaultActions:
    - log
  rules:
    - event: %s
      actions:
        - log
`, eventName)

	validJSONPolicy := fmt.Sprintf(`{
  "apiVersion": "tracee.aquasec.com/v1beta1",
  "kind": "Policy",
  "metadata": {
    "name": "test-json-policy",
    "annotations": {
      "description": "Test JSON policy"
    }
  },
  "spec": {
    "scope": [
      "global"
    ],
    "defaultActions": [
      "log"
    ],
    "rules": [
      {
        "event": "%s",
        "actions": [
          "log"
        ]
      }
    ]
  }
}`, eventName)

	invalidYAMLPolicy := `apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: invalid-yaml
spec:
  scope:
    - global
  rules:
    - event: fake_signature
invalid: yaml: syntax
`

	invalidJSONPolicy := `{
  "apiVersion": "tracee.aquasec.com/v1beta1",
  "kind": "Policy",
  "metadata": {
    "name": "invalid-json",
    "annotations": {
      "description": "Invalid JSON"
    }
  },
  "spec": {
    "scope": [
      "global"
    ],
    "rules": [
      {
        "event": "fake_signature"
      }
    ]
  },
  invalid json syntax
}`

	tests := []struct {
		testName      string
		setupFiles    func(t *testing.T) []string
		expectedCount int
		expectError   bool
		errorContains string
	}{
		{
			testName: "load single YAML file",
			setupFiles: func(t *testing.T) []string {
				tempDir := t.TempDir()
				policyFile := filepath.Join(tempDir, "policy.yaml")
				err := os.WriteFile(policyFile, []byte(validYAMLPolicy), 0644)
				assert.NilError(t, err)
				return []string{policyFile}
			},
			expectedCount: 1,
			expectError:   false,
		},
		{
			testName: "load single JSON file",
			setupFiles: func(t *testing.T) []string {
				tempDir := t.TempDir()
				policyFile := filepath.Join(tempDir, "policy.json")
				err := os.WriteFile(policyFile, []byte(validJSONPolicy), 0644)
				assert.NilError(t, err)
				return []string{policyFile}
			},
			expectedCount: 1,
			expectError:   false,
		},
		{
			testName: "load directory with YAML files",
			setupFiles: func(t *testing.T) []string {
				tempDir := t.TempDir()
				for i := 0; i < 3; i++ {
					policyFile := filepath.Join(tempDir, fmt.Sprintf("policy%d.yaml", i))
					// Change policy name to make them unique
					policyContent := fmt.Sprintf(`apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: test-yaml-policy-%d
  annotations:
    description: Test YAML policy
spec:
  scope:
    - global
  defaultActions:
    - log
  rules:
    - event: %s
      actions:
        - log
`, i, eventName)
					err := os.WriteFile(policyFile, []byte(policyContent), 0644)
					assert.NilError(t, err)
				}
				return []string{tempDir}
			},
			expectedCount: 3,
			expectError:   false,
		},
		{
			testName: "load directory with JSON files",
			setupFiles: func(t *testing.T) []string {
				tempDir := t.TempDir()
				for i := 0; i < 3; i++ {
					policyFile := filepath.Join(tempDir, fmt.Sprintf("policy%d.json", i))
					policyContent := fmt.Sprintf(`{
  "apiVersion": "tracee.aquasec.com/v1beta1",
  "kind": "Policy",
  "metadata": {
    "name": "test-json-policy-%d",
    "annotations": {
      "description": "Test JSON policy"
    }
  },
  "spec": {
    "scope": [
      "global"
    ],
    "defaultActions": [
      "log"
    ],
    "rules": [
      {
        "event": "%s",
        "actions": [
          "log"
        ]
      }
    ]
  }
}`, i, eventName)
					err := os.WriteFile(policyFile, []byte(policyContent), 0644)
					assert.NilError(t, err)
				}
				return []string{tempDir}
			},
			expectedCount: 3,
			expectError:   false,
		},
		{
			testName: "load directory with mixed YAML and JSON files",
			setupFiles: func(t *testing.T) []string {
				tempDir := t.TempDir()
				// Create YAML files
				for i := 0; i < 2; i++ {
					policyFile := filepath.Join(tempDir, fmt.Sprintf("policy-yaml-%d.yaml", i))
					policyContent := fmt.Sprintf(`apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: test-yaml-policy-%d
  annotations:
    description: Test YAML policy
spec:
  scope:
    - global
  defaultActions:
    - log
  rules:
    - event: %s
      actions:
        - log
`, i, eventName)
					err := os.WriteFile(policyFile, []byte(policyContent), 0644)
					assert.NilError(t, err)
				}
				// Create JSON files
				for i := 0; i < 2; i++ {
					policyFile := filepath.Join(tempDir, fmt.Sprintf("policy-json-%d.json", i))
					policyContent := fmt.Sprintf(`{
  "apiVersion": "tracee.aquasec.com/v1beta1",
  "kind": "Policy",
  "metadata": {
    "name": "test-json-policy-%d",
    "annotations": {
      "description": "Test JSON policy"
    }
  },
  "spec": {
    "scope": [
      "global"
    ],
    "defaultActions": [
      "log"
    ],
    "rules": [
      {
        "event": "%s",
        "actions": [
          "log"
        ]
      }
    ]
  }
}`, i, eventName)
					err := os.WriteFile(policyFile, []byte(policyContent), 0644)
					assert.NilError(t, err)
				}
				return []string{tempDir}
			},
			expectedCount: 4,
			expectError:   false,
		},
		{
			testName: "load directory ignores non-policy files",
			setupFiles: func(t *testing.T) []string {
				tempDir := t.TempDir()
				// Create valid policy files
				policyFile1 := filepath.Join(tempDir, "policy1.yaml")
				err := os.WriteFile(policyFile1, []byte(validYAMLPolicy), 0644)
				assert.NilError(t, err)

				policyFile2 := filepath.Join(tempDir, "policy2.json")
				err = os.WriteFile(policyFile2, []byte(validJSONPolicy), 0644)
				assert.NilError(t, err)

				// Create non-policy files that should be ignored
				otherFile1 := filepath.Join(tempDir, "readme.txt")
				err = os.WriteFile(otherFile1, []byte("This is a readme"), 0644)
				assert.NilError(t, err)

				otherFile2 := filepath.Join(tempDir, "config.xml")
				err = os.WriteFile(otherFile2, []byte("<config></config>"), 0644)
				assert.NilError(t, err)

				return []string{tempDir}
			},
			expectedCount: 2,
			expectError:   false,
		},
		{
			testName: "error on invalid YAML file",
			setupFiles: func(t *testing.T) []string {
				tempDir := t.TempDir()
				policyFile := filepath.Join(tempDir, "invalid.yaml")
				err := os.WriteFile(policyFile, []byte(invalidYAMLPolicy), 0644)
				assert.NilError(t, err)
				return []string{policyFile}
			},
			expectedCount: 0,
			expectError:   true,
			errorContains: "yaml",
		},
		{
			testName: "error on invalid JSON file",
			setupFiles: func(t *testing.T) []string {
				tempDir := t.TempDir()
				policyFile := filepath.Join(tempDir, "invalid.json")
				err := os.WriteFile(policyFile, []byte(invalidJSONPolicy), 0644)
				assert.NilError(t, err)
				return []string{policyFile}
			},
			expectedCount: 0,
			expectError:   true,
			errorContains: "invalid character",
		},
		{
			testName: "error on empty path",
			setupFiles: func(t *testing.T) []string {
				return []string{""}
			},
			expectedCount: 0,
			expectError:   true,
			errorContains: "policy path cannot be empty",
		},
		{
			testName: "error on non-existent file",
			setupFiles: func(t *testing.T) []string {
				tempDir := t.TempDir()
				return []string{filepath.Join(tempDir, "non-existent.yaml")}
			},
			expectedCount: 0,
			expectError:   true,
		},
		{
			testName: "error on duplicate policy names in directory",
			setupFiles: func(t *testing.T) []string {
				tempDir := t.TempDir()
				// Create two files with same policy name
				policyFile1 := filepath.Join(tempDir, "policy1.yaml")
				err := os.WriteFile(policyFile1, []byte(validYAMLPolicy), 0644)
				assert.NilError(t, err)

				policyFile2 := filepath.Join(tempDir, "policy2.json")
				// Use same policy name
				duplicatePolicy := fmt.Sprintf(`{
  "apiVersion": "tracee.aquasec.com/v1beta1",
  "kind": "Policy",
  "metadata": {
    "name": "test-yaml-policy",
    "annotations": {
      "description": "Duplicate policy name"
    }
  },
  "spec": {
    "scope": [
      "global"
    ],
    "defaultActions": [
      "log"
    ],
    "rules": [
      {
        "event": "%s",
        "actions": [
          "log"
        ]
      }
    ]
  }
}`, eventName)
				err = os.WriteFile(policyFile2, []byte(duplicatePolicy), 0644)
				assert.NilError(t, err)
				return []string{tempDir}
			},
			expectedCount: 0,
			expectError:   true,
			errorContains: "already exist",
		},
		{
			testName: "load multiple paths with YAML and JSON",
			setupFiles: func(t *testing.T) []string {
				tempDir := t.TempDir()
				// Create YAML file
				yamlFile := filepath.Join(tempDir, "policy.yaml")
				err := os.WriteFile(yamlFile, []byte(validYAMLPolicy), 0644)
				assert.NilError(t, err)

				// Create JSON file
				jsonFile := filepath.Join(tempDir, "policy.json")
				jsonPolicy := fmt.Sprintf(`{
  "apiVersion": "tracee.aquasec.com/v1beta1",
  "kind": "Policy",
  "metadata": {
    "name": "test-json-policy-separate",
    "annotations": {
      "description": "Test JSON policy"
    }
  },
  "spec": {
    "scope": [
      "global"
    ],
    "defaultActions": [
      "log"
    ],
    "rules": [
      {
        "event": "%s",
        "actions": [
          "log"
        ]
      }
    ]
  }
}`, eventName)
				err = os.WriteFile(jsonFile, []byte(jsonPolicy), 0644)
				assert.NilError(t, err)

				return []string{yamlFile, jsonFile}
			},
			expectedCount: 2,
			expectError:   false,
		},
		{
			testName: "load directory with .yml extension",
			setupFiles: func(t *testing.T) []string {
				tempDir := t.TempDir()
				policyFile := filepath.Join(tempDir, "policy.yml")
				err := os.WriteFile(policyFile, []byte(validYAMLPolicy), 0644)
				assert.NilError(t, err)
				return []string{tempDir}
			},
			expectedCount: 1,
			expectError:   false,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.testName, func(t *testing.T) {
			t.Parallel()

			paths := test.setupFiles(t)
			policies, err := PoliciesFromPaths(paths)

			if test.expectError {
				assert.Assert(t, err != nil, "expected error but got none")
				if test.errorContains != "" {
					assert.ErrorContains(t, err, test.errorContains)
				}
				assert.Equal(t, len(policies), 0, "expected no policies on error")
			} else {
				assert.NilError(t, err, "unexpected error: %v", err)
				assert.Equal(t, len(policies), test.expectedCount, "expected %d policies, got %d", test.expectedCount, len(policies))

				// Verify policy names are correct
				for i, policy := range policies {
					assert.Assert(t, policy.GetName() != "", "policy %d should have a name", i)
				}
			}
		})
	}
}

func TestPeekPolicyFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName       string
		fileContent    string
		expectedFormat PolicyFormat
		expectError    bool
	}{
		{
			testName: "detect plain YAML format",
			fileContent: `type: policy
name: test-policy
description: Test policy
scope:
  - global
rules:
  - event: sched_process_exec
`,
			expectedFormat: FormatPlainYAML,
			expectError:    false,
		},
		{
			testName: "detect K8s CRD format",
			fileContent: `apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: test-policy
  annotations:
    description: Test policy
spec:
  scope:
    - global
  rules:
    - event: sched_process_exec
`,
			expectedFormat: FormatK8sCRD,
			expectError:    false,
		},
		{
			testName: "detect K8s CRD format with different type field",
			fileContent: `type: something-else
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: test-policy
spec:
  scope:
    - global
  rules:
    - event: sched_process_exec
`,
			expectedFormat: FormatK8sCRD,
			expectError:    false,
		},
		{
			testName: "invalid format - no type or apiVersion",
			fileContent: `name: test-policy
scope:
  - global
rules:
  - event: sched_process_exec
`,
			expectedFormat: "",
			expectError:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			t.Parallel()

			data := []byte(test.fileContent)
			format, err := peekPolicyFormat(data, false)
			if test.expectError {
				assert.Assert(t, err != nil, "expected error but got none")
			} else {
				assert.NilError(t, err)
				assert.Equal(t, format, test.expectedFormat)
			}
		})
	}
}

func TestPeekPolicyFormatJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName       string
		fileContent    string
		expectedFormat PolicyFormat
		expectError    bool
	}{
		{
			testName: "detect plain JSON format",
			fileContent: `{
  "type": "policy",
  "name": "test-policy",
  "description": "Test policy",
  "scope": ["global"],
  "rules": [{"event": "sched_process_exec"}]
}`,
			expectedFormat: FormatPlainYAML,
			expectError:    false,
		},
		{
			testName: "detect K8s CRD JSON format",
			fileContent: `{
  "apiVersion": "tracee.aquasec.com/v1beta1",
  "kind": "Policy",
  "metadata": {
    "name": "test-policy",
    "annotations": {
      "description": "Test policy"
    }
  },
  "spec": {
    "scope": ["global"],
    "rules": [{"event": "sched_process_exec"}]
  }
}`,
			expectedFormat: FormatK8sCRD,
			expectError:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			t.Parallel()

			data := []byte(test.fileContent)
			format, err := peekPolicyFormat(data, true)
			if test.expectError {
				assert.Assert(t, err != nil, "expected error but got none")
			} else {
				assert.NilError(t, err)
				assert.Equal(t, format, test.expectedFormat)
			}
		})
	}
}

func TestFromPlainPolicySpec(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName    string
		spec        *PlainPolicySpec
		expectError bool
		validate    func(t *testing.T, pf PolicyFile)
	}{
		{
			testName: "valid plain policy spec",
			spec: &PlainPolicySpec{
				Type:        "policy",
				Name:        "test-policy",
				Description: "Test policy description",
				Scope:       []string{"global"},
				Rules: []k8s.Rule{
					{Event: "sched_process_exec"},
				},
				DefaultActions: []string{"log"},
			},
			expectError: false,
			validate: func(t *testing.T, pf PolicyFile) {
				assert.Equal(t, pf.APIVersion, "tracee.aquasec.com/v1beta1")
				assert.Equal(t, pf.Kind, "Policy")
				assert.Equal(t, pf.GetName(), "test-policy")
				assert.Equal(t, pf.GetDescription(), "Test policy description")
				assert.Equal(t, len(pf.GetScope()), 1)
				assert.Equal(t, pf.GetScope()[0], "global")
				assert.Equal(t, len(pf.GetRules()), 1)
				assert.Equal(t, pf.GetRules()[0].Event, "sched_process_exec")
				assert.Equal(t, len(pf.GetDefaultActions()), 1)
				assert.Equal(t, pf.GetDefaultActions()[0], "log")
			},
		},
		{
			testName: "missing type",
			spec: &PlainPolicySpec{
				Name:        "test-policy",
				Description: "Test policy",
				Scope:       []string{"global"},
				Rules:       []k8s.Rule{{Event: "sched_process_exec"}},
			},
			expectError: true,
			validate:    nil,
		},
		{
			testName: "invalid type",
			spec: &PlainPolicySpec{
				Type:        "invalid",
				Name:        "test-policy",
				Description: "Test policy",
				Scope:       []string{"global"},
				Rules:       []k8s.Rule{{Event: "sched_process_exec"}},
			},
			expectError: true,
			validate:    nil,
		},
		{
			testName: "missing name (validated by PolicyFile.Validate)",
			spec: &PlainPolicySpec{
				Type:        "policy",
				Description: "Test policy",
				Scope:       []string{"global"},
				Rules:       []k8s.Rule{{Event: "sched_process_exec"}},
			},
			expectError: false, // Conversion succeeds, validation happens in Validate()
			validate:    nil,
		},
		{
			testName: "missing description (validated by PolicyFile.Validate)",
			spec: &PlainPolicySpec{
				Type:  "policy",
				Name:  "test-policy",
				Scope: []string{"global"},
				Rules: []k8s.Rule{{Event: "sched_process_exec"}},
			},
			expectError: false, // Conversion succeeds, validation happens in Validate()
			validate:    nil,
		},
		{
			testName: "empty scope (validated by PolicyFile.Validate)",
			spec: &PlainPolicySpec{
				Type:        "policy",
				Name:        "test-policy",
				Description: "Test policy",
				Scope:       []string{},
				Rules:       []k8s.Rule{{Event: "sched_process_exec"}},
			},
			expectError: false, // Conversion succeeds, validation happens in Validate()
			validate:    nil,
		},
		{
			testName: "empty rules (validated by PolicyFile.Validate)",
			spec: &PlainPolicySpec{
				Type:        "policy",
				Name:        "test-policy",
				Description: "Test policy",
				Scope:       []string{"global"},
				Rules:       []k8s.Rule{},
			},
			expectError: false, // Conversion succeeds, validation happens in Validate()
			validate:    nil,
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			t.Parallel()

			pf, err := getPolicyFileFromPlainPolicy(test.spec)
			if test.expectError {
				assert.Assert(t, err != nil, "expected error but got none")
			} else {
				assert.NilError(t, err)
				if test.validate != nil {
					test.validate(t, pf)
				}
			}
		})
	}
}

func TestPlainYAMLPolicyLoading(t *testing.T) {
	t.Parallel()

	eventName := "sched_process_exec"
	validPlainYAML := fmt.Sprintf(`type: policy
name: plain-test-policy
description: Test plain YAML policy
scope:
  - global
rules:
  - event: %s
`, eventName)

	tests := []struct {
		testName    string
		setupFiles  func(t *testing.T) []string
		expectError bool
		validate    func(t *testing.T, policies []k8s.PolicyInterface)
	}{
		{
			testName: "load plain YAML policy",
			setupFiles: func(t *testing.T) []string {
				tempDir := t.TempDir()
				policyFile := filepath.Join(tempDir, "policy.yaml")
				err := os.WriteFile(policyFile, []byte(validPlainYAML), 0644)
				assert.NilError(t, err)
				return []string{policyFile}
			},
			expectError: false,
			validate: func(t *testing.T, policies []k8s.PolicyInterface) {
				assert.Equal(t, len(policies), 1)
				assert.Equal(t, policies[0].GetName(), "plain-test-policy")
				assert.Equal(t, policies[0].GetDescription(), "Test plain YAML policy")
				assert.Equal(t, len(policies[0].GetScope()), 1)
				assert.Equal(t, policies[0].GetScope()[0], "global")
				assert.Equal(t, len(policies[0].GetRules()), 1)
				assert.Equal(t, policies[0].GetRules()[0].Event, eventName)
			},
		},
		{
			testName: "load mixed formats from directory",
			setupFiles: func(t *testing.T) []string {
				tempDir := t.TempDir()

				// Create plain YAML file
				plainFile := filepath.Join(tempDir, "plain.yaml")
				err := os.WriteFile(plainFile, []byte(validPlainYAML), 0644)
				assert.NilError(t, err)

				// Create K8s CRD YAML file
				k8sFile := filepath.Join(tempDir, "k8s.yaml")
				k8sPolicy := fmt.Sprintf(`apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: k8s-test-policy
  annotations:
    description: Test K8s CRD policy
spec:
  scope:
    - global
  rules:
    - event: %s
`, eventName)
				err = os.WriteFile(k8sFile, []byte(k8sPolicy), 0644)
				assert.NilError(t, err)

				return []string{tempDir}
			},
			expectError: false,
			validate: func(t *testing.T, policies []k8s.PolicyInterface) {
				assert.Equal(t, len(policies), 2)
				names := make(map[string]bool)
				for _, p := range policies {
					names[p.GetName()] = true
				}
				assert.Assert(t, names["plain-test-policy"])
				assert.Assert(t, names["k8s-test-policy"])
			},
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			t.Parallel()

			paths := test.setupFiles(t)
			policies, err := PoliciesFromPaths(paths)

			if test.expectError {
				assert.Error(t, err, "expected error but got none")
			} else {
				assert.NilError(t, err)
				if test.validate != nil {
					test.validate(t, policies)
				}
			}
		})
	}
}
