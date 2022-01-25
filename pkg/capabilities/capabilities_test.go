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

	newpid2 func(int) (capability.Capabilities, error)
	get     func(capability.CapType, capability.Cap) bool
	load    func() error
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

func (f fakeCapability) NewPid2(pid int) (capability.Capabilities, error) {
	if f.newpid2 != nil {
		return f.newpid2(pid)
	}
	return nil, nil
}

func TestCheckRequiredCapabilities(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		require.NoError(t, CheckRequired(fakeCapability{}, []capability.Cap{capability.CAP_SYS_ADMIN, capability.CAP_IPC_LOCK}))
	})

	t.Run("missing CAP_SYS_ADMIN", func(t *testing.T) {
		err := CheckRequired(fakeCapability{get: func(capType capability.CapType, c capability.Cap) bool {
			assert.Equal(t, capability.EFFECTIVE, capType)
			assert.Equal(t, capability.CAP_SYS_ADMIN, c)
			return false
		}}, []capability.Cap{capability.CAP_SYS_ADMIN})
		assert.Equal(t, "insufficient privileges to run: missing CAP_SYS_ADMIN", err.Error())
	})
}

func TestLoadSelfCapabilities(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		oldNewPid2 := NewPid2
		defer func() {
			NewPid2 = oldNewPid2
		}()

		var orderOfFuncs []string
		NewPid2 = fakeCapability{newpid2: func(i int) (capability.Capabilities, error) {
			orderOfFuncs = append(orderOfFuncs, "NewPid2")
			return fakeCapability{
				load: func() error {
					orderOfFuncs = append(orderOfFuncs, "Load")
					return nil
				},
			}, nil
		}}.newpid2
		sc, err := Self()
		require.NoError(t, err)
		require.NotNil(t, sc)
		require.Equal(t, []string{"NewPid2", "Load"}, orderOfFuncs)
	})

	t.Run("sad path - NewPid2 fails", func(t *testing.T) {
		oldNewPid2 := NewPid2
		defer func() {
			NewPid2 = oldNewPid2
		}()

		NewPid2 = fakeCapability{newpid2: func(i int) (capability.Capabilities, error) {
			return nil, fmt.Errorf("newPid2 failed")
		}}.newpid2
		sc, err := Self()
		require.EqualError(t, err, "newPid2 failed")
		require.Nil(t, sc)
	})

	t.Run("sad path - loading capabilities fails", func(t *testing.T) {
		oldNewPid2 := NewPid2
		defer func() {
			NewPid2 = oldNewPid2
		}()

		NewPid2 = fakeCapability{newpid2: func(i int) (capability.Capabilities, error) {
			return fakeCapability{load: func() error {
				return fmt.Errorf("an error occurred")
			}}, nil
		}}.newpid2
		sc, err := Self()
		require.EqualError(t, err, "loading capabilities failed: an error occurred")
		require.Nil(t, sc)
	})
}
