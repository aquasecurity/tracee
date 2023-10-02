package http

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServer(t *testing.T) {
	t.Parallel()

	httpServer := New("")

	httpServer.EnableMetricsEndpoint()
	httpServer.EnableHealthzEndpoint()
	httpServer.EnablePProfEndpoint()

	server := httptest.NewServer(httpServer.mux)
	defer server.Close()

	tests := []struct {
		name     string
		endpoint string
		status   int
	}{
		{name: "TestHealthzEndpoint", endpoint: "/healthz", status: 200},
		{name: "TestMetricsEndpoint", endpoint: "/metrics", status: 200},
		{name: "TestPProfEndpoint", endpoint: "/debug/pprof", status: 200},
		{name: "TestIndexEndpoint", endpoint: "", status: 404},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := http.Get(fmt.Sprintf("%s%s", server.URL, tt.endpoint))
			assert.NoError(t, err)

			assert.Equal(t, tt.status, resp.StatusCode)
		})
	}
}
