package capabilities

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

type fakeCapability struct {
	cap.Value

	getPID  func(int) (ICapabilitiesSet, error)
	clear   func() error
	getFlag func(vec cap.Flag, val cap.Value) (bool, error)
	setFlag func(vec cap.Flag, enabled bool, val ...cap.Value) error
	setProc func() error
}

func (f fakeCapability) GetFlag(vec cap.Flag, val cap.Value) (bool, error) {
	if f.getFlag != nil {
		return f.getFlag(vec, val)
	}
	return true, nil
}

func (f fakeCapability) SetFlag(vec cap.Flag, enabled bool, val ...cap.Value) error {
	if f.setFlag != nil {
		return f.setFlag(vec, enabled, val...)
	}
	return nil
}

func (f fakeCapability) SetProc() error {
	if f.setProc != nil {
		return f.setProc()
	}
	return nil
}

func (f fakeCapability) Clear() error {
	if f.clear != nil {
		return f.clear()
	}
	return nil
}

func (f fakeCapability) GetPID(pid int) (ICapabilitiesSet, error) {
	if f.getPID != nil {
		return f.getPID(pid)
	}
	return nil, nil
}

func TestCheckRequiredCapabilities(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		require.NoError(t, CheckRequired(fakeCapability{}, []cap.Value{cap.SYS_ADMIN, cap.IPC_LOCK, cap.SYS_PTRACE}))
	})

	t.Run("missing CAP_SYS_ADMIN", func(t *testing.T) {
		err := CheckRequired(fakeCapability{getFlag: func(vec cap.Flag, val cap.Value) (bool, error) {
			assert.Equal(t, cap.Effective, vec)
			assert.Equal(t, cap.SYS_ADMIN, val)
			return false, nil
		}}, []cap.Value{cap.SYS_ADMIN})
		assert.Equal(t, "insufficient privileges to run: missing CAP_SYS_ADMIN", err.Error())
	})
}

func TestLoadSelfCapabilities(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		oldGetPID := GetPID
		defer func() {
			GetPID = oldGetPID
		}()

		var orderOfFuncs []string
		GetPID = fakeCapability{getPID: func(pid int) (ICapabilitiesSet, error) {
			orderOfFuncs = append(orderOfFuncs, "GetPID")
			return fakeCapability{}, nil
		}}.getPID
		sc, err := Self()
		require.NoError(t, err)
		require.NotNil(t, sc)
		require.Equal(t, []string{"GetPID"}, orderOfFuncs)
	})

	t.Run("sad path - GetPID fails", func(t *testing.T) {
		oldGetPID := GetPID
		defer func() {
			GetPID = oldGetPID
		}()

		GetPID = fakeCapability{getPID: func(pid int) (ICapabilitiesSet, error) {
			return nil, fmt.Errorf("getPID failed")
		}}.getPID
		sc, err := Self()
		require.EqualError(t, err, "getPID failed")
		require.Nil(t, sc)
	})
}

func TestDropUnrequired(t *testing.T) {
	requiredCaps := []cap.Value{cap.SYS_ADMIN, cap.IPC_LOCK, cap.SYS_PTRACE, cap.SYS_RESOURCE}
	t.Run("happy path", func(t *testing.T) {
		var setCaps []cap.Value
		fc := fakeCapability{
			setFlag: func(vec cap.Flag, enabled bool, val ...cap.Value) error {
				if enabled == true && vec == cap.Effective {
					setCaps = append(setCaps, val...)
				}
				return nil
			},
			setProc: func() error {
				if len(setCaps) != len(requiredCaps) {
					return fmt.Errorf("%d capabilities were set, but %d was required", len(setCaps), len(requiredCaps))
				}
				for _, reqCap := range requiredCaps {
					isFound := false
					for _, setCap := range setCaps {
						if reqCap == setCap {
							isFound = true
							break
						}
					}
					if isFound == false {
						return fmt.Errorf("capability %s was not set but was required", reqCap)
					}
				}
				return nil
			},
		}
		require.NoError(t, DropUnrequired(fc, requiredCaps))
	})
	t.Run("setProc error invoked", func(t *testing.T) {
		fc := fakeCapability{
			setProc: func() error {
				return fmt.Errorf("error in setProc")
			},
		}
		require.Error(t, DropUnrequired(fc, requiredCaps))
	})
}
