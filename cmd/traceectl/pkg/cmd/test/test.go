package test

import (
	"bytes"
	"testing"
	"time"

	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/mock"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/models"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

func runMockServer(t *testing.T) *grpc.Server {
	mockServer, err := mock.StartMockServer()
	if err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	return mockServer
}
func TestCommand(t *testing.T, testCase models.TestCase, rootCmd *cobra.Command) {
	server := runMockServer(t)
	defer server.Stop()
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs(testCase.OutputSlice)
	err := rootCmd.Execute()
	output := buf.String()
	if err != nil && testCase.ExpectedError == nil {
		t.Errorf("Unexpected error for test %s: %v", testCase.TestName, err)
		return
	}
	if err == nil && testCase.ExpectedError != nil {
		t.Errorf("Expected error for test %s but got none", testCase.TestName)
		return
	}
	if testCase.ExpectedError != nil {
		assert.ErrorContains(t, err, testCase.ExpectedError.Error())
	} else {
		assert.Contains(t, output, testCase.ExpectedPrinter)

	}
}
