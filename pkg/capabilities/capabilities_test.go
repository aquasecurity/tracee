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

func TestCheckRequiredCapabilities(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		err := checkRequired(fakeCapability{}, []cap.Value{cap.SYS_ADMIN, cap.IPC_LOCK, cap.SYS_PTRACE})
		assert.NoError(t, err)
	})

	t.Run("missing single capability", func(t *testing.T) {
		err := checkRequired(fakeCapability{getFlag: func(vec cap.Flag, val cap.Value) (bool, error) {
			assert.Equal(t, cap.Effective, vec)
			assert.Equal(t, cap.SYS_ADMIN, val)
			return false, nil
		}}, []cap.Value{cap.SYS_ADMIN})
		require.IsType(t, &MissingCapabilitiesError{}, err)
		assert.ElementsMatch(t, []cap.Value{cap.SYS_ADMIN}, err.(*MissingCapabilitiesError).MissingCaps)
	})

	t.Run("missing multiple capabilities", func(t *testing.T) {
		reqCaps := []cap.Value{cap.SYS_ADMIN, cap.IPC_LOCK, cap.SYS_PTRACE}
		err := checkRequired(fakeCapability{getFlag: func(vec cap.Flag, val cap.Value) (bool, error) {
			assert.Equal(t, cap.Effective, vec)
			return false, nil
		}}, reqCaps)
		require.IsType(t, &MissingCapabilitiesError{}, err)
		assert.ElementsMatch(t, reqCaps, err.(*MissingCapabilitiesError).MissingCaps)
	})

	t.Run("error with 'cap' library", func(t *testing.T) {
		err := checkRequired(fakeCapability{getFlag: func(vec cap.Flag, val cap.Value) (bool, error) {
			return false, cap.ErrBadSet
		}}, []cap.Value{cap.SYS_ADMIN})
		assert.ErrorIs(t, err, cap.ErrBadSet)
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
		require.NoError(t, dropUnrequired(fc, requiredCaps))
	})
	t.Run("Sad flow", func(t *testing.T) {
		t.Run("setProc error invoked", func(t *testing.T) {
			fc := fakeCapability{
				setProc: func() error {
					return fmt.Errorf("error in setProc")
				},
			}
			err := dropUnrequired(fc, requiredCaps)
			require.Error(t, err)
			assert.IsType(t, &DropCapabilitiesError{}, err)
		})
		t.Run("setFlag error invoked", func(t *testing.T) {
			fc := fakeCapability{
				setFlag: func(vec cap.Flag, enabled bool, val ...cap.Value) error {
					return cap.ErrBadSet
				},
			}
			err := dropUnrequired(fc, requiredCaps)
			require.Error(t, err)
			assert.IsType(t, cap.ErrBadSet, err)
			assert.ErrorIs(t, err, cap.ErrBadSet)
		})
	})
}
