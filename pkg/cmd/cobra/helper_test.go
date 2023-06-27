package cobra

import (
	"testing"

	"gotest.tools/assert"

	"github.com/aquasecurity/tracee/pkg/policy"
)

func Test_getOutputFlagsFromPolicies(t *testing.T) {
	tests := []struct {
		name                string
		outputFlags         []string
		policyFiles         []policy.PolicyFile
		expectedOutputFlags []string
		errorMsg            string
	}{
		{
			name:        "no output flags, with action log",
			outputFlags: []string{},
			policyFiles: []policy.PolicyFile{
				{
					Name:           "test",
					DefaultActions: []string{"log"},
					Rules: []policy.Rule{
						{Event: "test"},
					},
				},
			},
			expectedOutputFlags: []string{"table:stdout"},
		},
		{
			name: "output options",
			outputFlags: []string{
				"option:stack-addresses",
				"option:exec-env",
				"option:relative-time",
				"option:exec-hash",
				"option:parse-arguments",
				"option:parse-arguments-fds",
				"option:sort-events",
			},
			policyFiles: []policy.PolicyFile{
				{
					Name:           "test",
					DefaultActions: []string{"log"},
					Rules: []policy.Rule{
						{Event: "test"},
					},
				},
			},
			expectedOutputFlags: []string{
				"option:stack-addresses",
				"option:exec-env",
				"option:relative-time",
				"option:exec-hash",
				"option:parse-arguments",
				"option:parse-arguments-fds",
				"option:sort-events",
				"table:stdout",
			},
		},
		{
			name:        "no output flags, with action webhook",
			outputFlags: []string{""},
			policyFiles: []policy.PolicyFile{
				{
					Name:           "test",
					DefaultActions: []string{"webhook"},
					Rules: []policy.Rule{
						{Event: "test"},
					},
				},
			},
			errorMsg: "cobra.getOutputFlagsFromPolicies: policy action \"webhook\" has no printer configured, please configure the printer with --output",
		},
		{
			name:        "no output flags, with action forward",
			outputFlags: []string{""},
			policyFiles: []policy.PolicyFile{
				{
					Name:           "test",
					DefaultActions: []string{"forward"},
					Rules: []policy.Rule{
						{Event: "test"},
					},
				},
			},
			errorMsg: "cobra.getOutputFlagsFromPolicies: policy action \"forward\" has no printer configured, please configure the printer with --output",
		},
		{
			name:        "webhook printer, with action webhook and log",
			outputFlags: []string{"webhook:http://localhost:8080"},
			policyFiles: []policy.PolicyFile{
				{
					Name:           "test",
					DefaultActions: []string{"log"},
					Rules: []policy.Rule{
						{
							Event:   "test",
							Actions: []string{"webhook"},
						},
					},
				},
			},
			expectedOutputFlags: []string{"webhook:http://localhost:8080", "table:stdout"},
		},
		{
			name:        "forward printer, with action forward and log",
			outputFlags: []string{"forward:http://localhost:8080"},
			policyFiles: []policy.PolicyFile{
				{
					Name:           "test",
					DefaultActions: []string{"log"},
					Rules: []policy.Rule{
						{
							Event:   "test",
							Actions: []string{"forward"},
						},
					},
				},
			},
			expectedOutputFlags: []string{"forward:http://localhost:8080", "table:stdout"},
		},
		{
			name:        "table printer, with action log",
			outputFlags: []string{"table"},
			policyFiles: []policy.PolicyFile{
				{
					Name:           "test",
					DefaultActions: []string{"log"},
					Rules: []policy.Rule{
						{
							Event: "test",
						},
					},
				},
			},
			expectedOutputFlags: []string{"table"},
		},
		{
			name:        "table:/log.txt printer, with action log",
			outputFlags: []string{"table:/log.txt"},
			policyFiles: []policy.PolicyFile{
				{
					Name:           "test",
					DefaultActions: []string{"log"},
					Rules: []policy.Rule{
						{
							Event: "test",
						},
					},
				},
			},
			expectedOutputFlags: []string{"table:/log.txt"},
		},
		{
			name:        "json and table:/log.txt printer, with action log",
			outputFlags: []string{"json", "table:/log.txt"},
			policyFiles: []policy.PolicyFile{
				{
					Name:           "test",
					DefaultActions: []string{"log"},
					Rules: []policy.Rule{
						{
							Event: "test",
						},
					},
				},
			},
			expectedOutputFlags: []string{"json", "table:/log.txt"},
		},
		{
			name:        "multiple policies with all actions",
			outputFlags: []string{"forward:tcp://localhost:24224", "webhook:http://localhost:8080"},
			policyFiles: []policy.PolicyFile{
				{
					Name:           "test",
					DefaultActions: []string{"log"},
					Rules: []policy.Rule{
						{
							Event: "event1",
						},
						{
							Event:   "event2",
							Actions: []string{"webhook"},
						},
						{
							Event:   "event3",
							Actions: []string{"forward"},
						},
					},
				},
				{
					Name:           "test2",
					DefaultActions: []string{"webhook"},
					Rules: []policy.Rule{
						{
							Event: "event1",
						},
						{
							Event:   "event2",
							Actions: []string{"log"},
						},
						{
							Event:   "event3",
							Actions: []string{"forward"},
						},
					},
				},
				{
					Name:           "test3",
					DefaultActions: []string{"forward"},
					Rules: []policy.Rule{
						{
							Event: "event1",
						},
						{
							Event:   "event2",
							Actions: []string{"log"},
						},
						{
							Event:   "event3",
							Actions: []string{"webhook"},
						},
					},
				},
			},
			expectedOutputFlags: []string{"forward:tcp://localhost:24224", "webhook:http://localhost:8080", "table:stdout"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputFlags, err := getOutputFlagsFromPolicies(tt.outputFlags, tt.policyFiles)
			if err != nil {
				assert.Equal(t, tt.errorMsg, err.Error())
				return
			}

			assert.NilError(t, err)
			assert.DeepEqual(t, tt.expectedOutputFlags, outputFlags)
		})
	}
}
