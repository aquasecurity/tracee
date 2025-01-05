package server

import (
	"testing"

	"github.com/aquasecurity/tracee/pkg/server/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrepareServer(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		testName       string
		serverFlags    []string
		expectedServer *Server
		expectedError  error
	}{
		{
			testName:    "http server only",
			serverFlags: []string{"http.address=127.0.0.1:8080"},
			expectedServer: &Server{
				HTTPServer: http.New("127.0.0.1:8080"),
			},
			expectedError: nil,
		},
	}
	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			server, err := PrepareServer(testcase.serverFlags)
			if err != nil {
				require.NotNil(t, testcase.expectedError)
				assert.Contains(t, err.Error(), testcase.expectedError.Error())
			} else {
				assert.Equal(t, testcase.expectedServer, server)
			}

		})
	}
}
