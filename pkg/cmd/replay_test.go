package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/config"
)

func TestReplayRunner_Run_EmptyPath(t *testing.T) {
	t.Parallel()

	runner := ReplayRunner{}
	err := runner.Run(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replay path cannot be empty")
}

func TestReplayRunner_Run_MissingFile(t *testing.T) {
	t.Parallel()

	runner := ReplayRunner{
		ReplayPath: filepath.Join(t.TempDir(), "does-not-exist.json"),
	}
	err := runner.Run(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open replay file")
}

func TestReplayRunner_Run_NoDetectors(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "events.json")
	require.NoError(t, os.WriteFile(path, []byte("{}\n"), 0o644))

	runner := ReplayRunner{
		ReplayPath:   path,
		TraceeConfig: config.Config{},
	}
	err := runner.Run(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no detectors available")
}

func TestCreateReplayPrinter_DefaultsToJSONStdout(t *testing.T) {
	t.Parallel()

	for _, cfg := range []*config.OutputConfig{nil, {}} {
		p, err := createReplayPrinter(cfg)
		require.NoError(t, err)
		require.NotNil(t, p)
		assert.Equal(t, "json", p.Kind())
	}
}

func TestCreateReplayPrinter_NoDestinations(t *testing.T) {
	t.Parallel()

	cfg := &config.OutputConfig{
		Streams: []config.Stream{{}},
	}
	_, err := createReplayPrinter(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no destinations in output stream")
}

func TestCreateReplayPrinter_SingleDestination(t *testing.T) {
	t.Parallel()

	tableDest, err := flags.PreparePrinterConfig("table", "stdout")
	require.NoError(t, err)

	cfg := &config.OutputConfig{
		Streams: []config.Stream{
			{Destinations: []config.Destination{tableDest}},
		},
	}
	p, err := createReplayPrinter(cfg)
	require.NoError(t, err)
	assert.Equal(t, "table", p.Kind())
}

func TestCreateReplayPrinter_RejectsMultipleDestinations(t *testing.T) {
	t.Parallel()

	tableDest, err := flags.PreparePrinterConfig("table", "stdout")
	require.NoError(t, err)
	jsonDest, err := flags.PreparePrinterConfig("json", "stdout")
	require.NoError(t, err)

	// Multiple destinations in one stream
	cfg := &config.OutputConfig{
		Streams: []config.Stream{
			{Destinations: []config.Destination{tableDest, jsonDest}},
		},
	}
	_, err = createReplayPrinter(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "single output destination")

	// Multiple streams
	cfg = &config.OutputConfig{
		Streams: []config.Stream{
			{Destinations: []config.Destination{tableDest}},
			{Destinations: []config.Destination{jsonDest}},
		},
	}
	_, err = createReplayPrinter(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "single output destination")
}
