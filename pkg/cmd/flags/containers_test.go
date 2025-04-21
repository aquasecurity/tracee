package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrepareContainers(t *testing.T) {
	tests := []struct {
		name           string
		containerFlags []string
		expectedEnrich bool
		expectedCgroup string
		expectError    bool
	}{
		{
			name:           "valid enrich flag",
			containerFlags: []string{"enrich=true"},
			expectedEnrich: false,
		},
		{
			name:           "disable enrichment",
			containerFlags: []string{"enrich=false"},
			expectedEnrich: true,
		},
		{
			name:           "valid socket flag",
			containerFlags: []string{"sockets.docker=/var/run/docker.sock"},
		},
		{
			name:           "valid cgroupfs flag",
			containerFlags: []string{"cgroupfs=/sys/fs/cgroup"},
			expectedCgroup: "/sys/fs/cgroup",
		},
		{
			name:           "invalid enrich flag",
			containerFlags: []string{"enrich=invalid"},
			expectError:    true,
		},
		{
			name:           "unsupported runtime",
			containerFlags: []string{"sockets.unknown=/path/to/socket"},
			expectError:    true,
		},
		{
			name:           "unknown flag",
			containerFlags: []string{"unknown=value"},
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, noEnrich, cgroupfs, err := PrepareContainers(tt.containerFlags)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedEnrich, noEnrich)
				assert.Equal(t, tt.expectedCgroup, cgroupfs)
			}
		})
	}
}
