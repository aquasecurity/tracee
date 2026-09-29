package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/config"
)

func TestFDPathMapEntries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		output *config.OutputConfig
		want   uint32
	}{
		{name: "no output config", output: nil, want: 1},
		{name: "disabled", output: &config.OutputConfig{}, want: 1},
		{name: "disabled ignores the capacity", output: &config.OutputConfig{FdPathsMaxEntries: 4096}, want: 1},
		{name: "enabled uses the default", output: &config.OutputConfig{FdPaths: true}, want: defaultFDPathEntries},
		{name: "enabled uses the capacity", output: &config.OutputConfig{FdPaths: true, FdPathsMaxEntries: 4096}, want: 4096},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, fdPathMapEntries(tt.output))
		})
	}
}
