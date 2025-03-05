package flags

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
	"github.com/aquasecurity/tracee/cmd/traceectl/test"
)

func TestPrepareServer(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		serverSlice    string
		expectedServer *client.Server
		expectedError  error
	}{
		{
			name:           "valid server address",
			serverSlice:    test.DefaultSocket,
			expectedServer: &client.Server{Addr: test.DefaultSocket},
			expectedError:  nil,
		},
		{
			name:           "invalid server address",
			serverSlice:    "invalid/path/tracee.sock",
			expectedServer: nil,
			expectedError:  fmt.Errorf("failed to get gRPC listening address"),
		},
		{
			name:           "empty server address",
			serverSlice:    "",
			expectedServer: nil,
			expectedError:  fmt.Errorf("server address cannot be empty"),
		},
	}

	mockServer, err := test.SetupMockSocket()
	if err != nil {
		t.Fatal(err)
	}
	for _, testcase := range testCases {
		t.Run(testcase.name, func(t *testing.T) {
			server, err := PrepareServer(testcase.serverSlice)
			if testcase.expectedError != nil {
				if assert.ErrorContains(t, err, testcase.expectedError.Error()) {
					return
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if assert.Equal(t, testcase.expectedServer, server) {
				return
			}
		})
	}
	if err := mockServer.TeardownMockSocket(); err != nil {
		t.Fatal(err)
	}
}
