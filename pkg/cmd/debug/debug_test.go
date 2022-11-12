package debug_test

import (
	"testing"

	"github.com/aquasecurity/tracee/pkg/cmd/debug"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDebug_Initial(t *testing.T) {
	assert.Equal(t, false, debug.Enabled())
}

func TestDebug_EnableDebug(t *testing.T) {
	err := debug.Enable()
	require.NoError(t, err)
	assert.Equal(t, true, debug.Enabled())
}

func TestDebug_DisableDebug(t *testing.T) {
	err := debug.Disable()
	require.NoError(t, err)
	assert.Equal(t, false, debug.Enabled())
}
