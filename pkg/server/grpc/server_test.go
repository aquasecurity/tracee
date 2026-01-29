package grpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServer_Address(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		protocol string
		addr     string
		expected string
	}{
		{
			name:     "tcp with port",
			protocol: "tcp",
			addr:     "4466",
			expected: "tcp:4466",
		},
		{
			name:     "unix socket",
			protocol: "unix",
			addr:     "/var/run/tracee.sock",
			expected: "unix:/var/run/tracee.sock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(tt.protocol, tt.addr)
			assert.Equal(t, tt.expected, s.Address())
		})
	}
}
