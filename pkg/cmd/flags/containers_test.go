package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrepareContainers(t *testing.T) {
	tests := []struct {
		name                string
		containerFlags      []string
		expectedNoEnrich    bool
		expectedCgroup      string
		expectedCgroupForce bool
		expectError         bool
	}{
		{
			name:             "valid enrich flag",
			containerFlags:   []string{"enrich=true"},
			expectedNoEnrich: false,
		},
		{
			name:             "disable enrichment",
			containerFlags:   []string{"enrich=false"},
			expectedNoEnrich: true,
		},
		{
			name:           "valid socket flag",
			containerFlags: []string{"sockets.docker=/var/run/docker.sock"},
		},
		{
			name:           "valid cgroupfs flag",
			containerFlags: []string{"cgroupfs.path=/sys/fs/cgroup"},
			expectedCgroup: "/sys/fs/cgroup",
		},
		{
			name:                "valid cgroupfs force flag",
			containerFlags:      []string{"cgroupfs.force=true"},
			expectedCgroupForce: true,
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
			res, err := PrepareContainers(tt.containerFlags)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedNoEnrich, res.NoEnrich)
				assert.Equal(t, tt.expectedCgroup, res.CgroupfsPath)
				assert.Equal(t, tt.expectedCgroupForce, res.CgroupfsForce)
			}
		})
	}
}
