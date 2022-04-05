package flags_test

import (
	"testing"

	"github.com/aquasecurity/tracee/cmd/tracee-ebpf/internal/flags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDebug_Initial(t *testing.T) {
	assert.Equal(t, false, flags.DebugModeEnabled())
}

func TestDebug_EnableDebug(t *testing.T) {
	err := flags.EnableDebugMode()
	require.NoError(t, err)
	assert.Equal(t, true, flags.DebugModeEnabled())
}

func TestDebug_DisableDebug(t *testing.T) {
	err := flags.DisableDebugMode()
	require.NoError(t, err)
	assert.Equal(t, false, flags.DebugModeEnabled())
}
