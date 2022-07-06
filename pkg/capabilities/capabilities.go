package capabilities

import (
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// CheckRequired check if given capabilities include all required capabilities in the effective set.
// If the error is of the MissingCapabilitiesError type, it means some capabilities are missing.
// Other errors might rise because of capabilities extraction failure, or internal errors.
func CheckRequired(reqCaps []cap.Value) error {
	selfCaps, err := getCurrentProcessCapabilities()
	if err != nil {
		return err
	}
	return checkRequired(selfCaps, reqCaps)
}

func checkRequired(caps set, reqCaps []cap.Value) error {
	var missingCaps []cap.Value
	for _, c := range reqCaps {
		exist, err := caps.GetFlag(cap.Effective, c)
		if err != nil {
			return err
		}
		if !exist {
			missingCaps = append(missingCaps, c)
		}
	}
	if len(missingCaps) > 0 {
		return &MissingCapabilitiesError{missingCaps}
	}
	return nil
}

// DropUnrequired drops all capabilities not required by user from Effective and Permitted set, and all capabilities
// from the Inheritance set.
// DropUnrequired requires that all required capabilities are already set or available in permitted set.
// The function also tries to drop the capabilities bounding set, but it won't work if CAP_SETPCAP is not available.
func DropUnrequired(reqCaps []cap.Value) error {
	selfCaps, err := getCurrentProcessCapabilities()
	if err != nil {
		return err
	}
	return dropUnrequired(selfCaps, reqCaps)
}

func dropUnrequired(selfCaps set, reqCaps []cap.Value) error {
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
		return &DropCapabilitiesError{err}
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

// set is an interface for the cap.Set type, created for testability.
type set interface {
	Clear() error
	GetFlag(vec cap.Flag, val cap.Value) (bool, error)
	SetFlag(vec cap.Flag, enabled bool, val ...cap.Value) error
	SetProc() error
}

func getCurrentProcessCapabilities() (*cap.Set, error) {
	return cap.GetPID(0)
}
