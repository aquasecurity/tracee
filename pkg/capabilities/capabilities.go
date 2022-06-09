package capabilities

import (
	"fmt"
	"strings"

	"kernel.org/pub/linux/libs/security/libcap/cap"
)

var (
	// GetPID is not defined on an interface
	// therefore it must be patched in for testability
	GetPID = func(pid int) (ICapabilitiesSet, error) {
		return cap.GetPID(pid)
	}
)

// ICapabilitiesSet is an interface for the cap.Set type, created for testability.
type ICapabilitiesSet interface {
	Clear() error
	GetFlag(vec cap.Flag, val cap.Value) (bool, error)
	SetFlag(vec cap.Flag, enabled bool, val ...cap.Value) error
	SetProc() error
}

func CheckRequired(caps ICapabilitiesSet, reqCaps []cap.Value) error {
	for _, c := range reqCaps {
		exist, err := caps.GetFlag(cap.Effective, c)
		if err != nil {
			return err
		}
		if !exist {
			return fmt.Errorf("insufficient privileges to run: missing %s", strings.ToUpper(c.String()))
		}
	}
	return nil
}

func Self() (ICapabilitiesSet, error) {
	return GetPID(0)
}

// DropUnrequired drops all capabilities not required by user from Effective and Permitted set, and all from the
// Inheritance set.
// DropUnrequired requires that all capabilities are already set or available in permitted set.
// The function also tries to drop the capabilities bounding set, but it won't work if CAP_SETPCAP is not available.
func DropUnrequired(selfCaps ICapabilitiesSet, reqCaps []cap.Value) error {
	// Dropping the bounding set is a best effort, so we ignore any error resulted from doing it.
	cap.DropBound(getAllCapabilities()...)
	err := selfCaps.Clear()
	if err != nil {
		return err
	}
	err = selfCaps.SetFlag(cap.Effective, true, reqCaps...)
	if err != nil {
		return err
	}
	err = selfCaps.SetFlag(cap.Permitted, true, reqCaps...)
	if err != nil {
		return err
	}
	// The inheritance set is set to be empty
	err = selfCaps.SetProc()
	if err != nil {
		return fmt.Errorf("couldn't drop capabilities: %v", err)
	}
	return nil
}

func getAllCapabilities() []cap.Value {
	var allCaps []cap.Value
	for capVal := cap.CHOWN; capVal < cap.MaxBits(); capVal++ {
		allCaps = append(allCaps, capVal)
	}
	return allCaps
}
