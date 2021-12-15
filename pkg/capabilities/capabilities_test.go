package capabilities

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/syndtr/gocapability/capability"
)

type fakeCapability struct {
	capability.Capabilities

	get  func(capability.CapType, capability.Cap) bool
	load func() error
}

func (f fakeCapability) Get(which capability.CapType, what capability.Cap) bool {
	if f.get != nil {
		return f.get(which, what)
	}
	return true
}

func (f fakeCapability) Load() error {
	if f.load != nil {
		return f.load()
	}
	return nil
}
func TestCheckRequiredCapabilities(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		require.NoError(t, CheckRequiredCapabilities(fakeCapability{}, []capability.Cap{capability.CAP_SYS_ADMIN, capability.CAP_IPC_LOCK}))
	})

	t.Run("missing CAP_SYS_ADMIN", func(t *testing.T) {
		err := CheckRequiredCapabilities(fakeCapability{get: func(capType capability.CapType, c capability.Cap) bool {
			assert.Equal(t, capability.EFFECTIVE, capType)
			assert.Equal(t, capability.CAP_SYS_ADMIN, c)
			return false
		}}, []capability.Cap{capability.CAP_SYS_ADMIN})
		assert.Equal(t, "insufficient privileges to run: missing CAP_SYS_ADMIN", err.Error())
	})
}

func TestLoadSelfCapabilities(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		sc, err := LoadSelfCapabilities(fakeCapability{})
		require.NoError(t, err)
		require.NotNil(t, sc)
	})

	t.Run("sad path - loading capabilities fails", func(t *testing.T) {
		sc, err := LoadSelfCapabilities(fakeCapability{load: func() error {
			return fmt.Errorf("an error occurred")
		}})
		require.EqualError(t, err, "loading capabilities failed: an error occurred")
		require.Nil(t, sc)
	})
}
