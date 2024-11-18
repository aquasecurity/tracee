package cmd

// import (
// 	"bytes"
// 	"testing"
// 	"time"

// 	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/mock"
// 	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/models"
// )

// var pluginTests = []models.TestCase{
// 	{
// 		Name:           "No plugin subcommand",
// 		Args:           []string{"plugin"},
// 		ExpectedOutput: "Error: requires at least 1 arg(s), only received 0\n", // Update expected output
// 	},
// }

// func TestPluginCmd(t *testing.T) {
// 	// Start the mock server
// 	mockServer, err := mock.StartMockServer()
// 	if err != nil {
// 		t.Fatalf("Failed to start mock server: %v", err)
// 	}
// 	defer mockServer.Stop() // Ensure the server is stopped after the test

// 	// Wait for the server to start
// 	time.Sleep(100 * time.Millisecond)

// 	for _, test := range pluginTests {
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

// 			if output != test.ExpectedOutput {
// 				t.Errorf("Expected output: %s, got: %s", test.ExpectedOutput, output)
// 			}
// 		})
// 	}
// }
