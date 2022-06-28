package capabilities

import (
	"fmt"
	"strings"

	"github.com/syndtr/gocapability/capability"
)

var (
	// NewPid2 is not defined on an interface
	// therefore it must be patched in for testability
	NewPid2 = capability.NewPid2
)

func CheckRequired(caps capability.Capabilities, reqCaps []capability.Cap) error {
	for _, c := range reqCaps {
		if !caps.Get(capability.EFFECTIVE, c) {
			return fmt.Errorf("insufficient privileges to run: missing CAP_%s", strings.ToUpper(c.String()))
		}
	}
	return nil
}

func Self() (capability.Capabilities, error) {
	selfCap, err := NewPid2(0)
	if err != nil {
		return nil, err
	}

	err = selfCap.Load()
	if err != nil {
		return nil, fmt.Errorf("loading capabilities failed: %s", err)
	}
	return selfCap, nil
}

// DropUnrequired requires that all capabilities are already set or available in permitted set.
// The function also tries to drop the capabilities bounding set, but it won't work if CAP_SETPCAP is not available.
func DropUnrequired(selfCaps capability.Capabilities, reqCaps []capability.Cap) error {
	selfCaps.Clear(capability.CAPS)
	for _, rc := range reqCaps {
		selfCaps.Set(capability.CAPS, rc)
	}
	err := selfCaps.Apply(capability.CAPS | capability.BOUNDS)
	if err != nil {
		return fmt.Errorf("couldn't drop capabilities: %v", err)
	}
	return nil
}
