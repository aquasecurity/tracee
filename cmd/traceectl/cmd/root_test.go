package cmd

// import (
// 	"bytes"
// 	"strings"
// 	"testing"
// 	"time"

// 	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/mock"
// 	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/models"
// )

// var rootTests = []models.TestCase{
// 	{
// 		Name:           "version",
// 		Args:           []string{"version"},
// 		ExpectedOutput: mock.ExpectedVersion,
// 	},
// 	{
// 		Name: "metrics",
// 		Args: []string{"metrics"},
// 		ExpectedOutput: (func() string {
// 			str := mock.ExpectedMetrics.String()      // convert to string
// 			str = strings.ReplaceAll(str, "  ", "\n") // add newlines
// 			str = strings.ReplaceAll(str, ":", ": ")  // add spaces
// 			return str
// 		})(),
// 	},
// }

// func TestRootCmd(t *testing.T) {
// 	// Start the mock server
// 	mockServer, err := mock.StartMockServer()
// 	if err != nil {
// 		t.Fatalf("Failed to start mock server: %v", err)
// 	}
// 	defer mockServer.Stop() // Ensure the server is stopped after the test

// 	// Wait for the server to start
// 	time.Sleep(100 * time.Millisecond)

// 	for _, test := range rootTests {
// 		t.Run(test.Name, func(t *testing.T) {
// 			// Capture output
// 			var buf bytes.Buffer
// 			rootCmd := GetRootCmd()
// 			rootCmd.SetOut(&buf)
// 			rootCmd.SetErr(&buf)

// 			// Set arguments for the test
// 			rootCmd.SetArgs(test.Args)

// 			// Execute the command
// 			if err := rootCmd.Execute(); err != nil {
// 				t.Error(t, err)
// 			}

// 			// Validate output and error (if any)
// 			output := buf.String()

// 			if !strings.Contains(output, test.ExpectedOutput.(string)) {
// 				t.Errorf("Expected output:\n%s\ngot:\n%s", test.ExpectedOutput, output)
// 			}
// 		})
// 	}
// }
