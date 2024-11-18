package cmd

// import (
// 	"bytes"
// 	"strings"
// 	"testing"
// 	"time"

// 	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/mock"
// 	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/models"
// 	pb "github.com/aquasecurity/tracee/api/v1beta1"
// )

// // test run the mock server and start the stream command
// // currently stream can connect to the server and print the output of events to the stream
// var streamTests = []models.TestCase{
// 	{
// 		Name:           "No subcommand",
// 		Args:           []string{"stream"},
// 		ExpectedOutput: mock.CreateEventsFromPolicies([]string{""}),
// 	},
// 	//TODO: add tests for subcommands
// }

// func TestStreamEvent(t *testing.T) {
// 	for _, test := range streamTests {
// 		t.Run(test.Name, func(t *testing.T) {
// 			// Start the mock server
// 			mockServer, err := mock.StartMockServer()
// 			if err != nil {
// 				t.Fatalf("Failed to start mock server: %v", err)
// 			}
// 			defer mockServer.Stop() // Ensure the server is stopped after the test

// 			// Wait for the server to start
// 			time.Sleep(100 * time.Millisecond)

// 			// Capture output
// 			var buf bytes.Buffer
// 			rootCmd.SetOut(&buf)
// 			rootCmd.SetErr(&buf)

// 			// Set arguments for the test
// 			rootCmd.SetArgs(test.Args)

// 			// Execute the command
// 			if err := rootCmd.Execute(); err != nil {
// 				t.Fatalf("Execute() failed: %v", err)
// 			}

// 			// Get the expected output
// 			if expectedEvents, ok := test.ExpectedOutput.([]*pb.StreamEventsResponse); ok {
// 				// Split the actual output by newlines
// 				actualEvents := strings.Split(strings.TrimSpace(buf.String()), "\n")
// 				// Check if the number of events match
// 				if len(actualEvents) != len(expectedEvents) {
// 					t.Errorf("Expected %d events, got %d", len(expectedEvents), len(actualEvents))
// 					return
// 				}

// 				// Compare each event
// 				for i, expected := range expectedEvents {
// 					if actualEvents[i] != expected.Event.String() {
// 						t.Errorf("Expected event %d: %q\nGot: %q", i, expected.Event.String(), actualEvents[i])
// 					}
// 				}
// 			} else {
// 				t.Errorf("Type assertion failed, expected output is not []*pb.StreamEventsResponse: %v", test.ExpectedOutput)
// 			}
// 		})
// 	}
// }
