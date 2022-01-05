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
