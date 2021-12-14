package capabilities

import (
	"fmt"
	"strings"

	"github.com/syndtr/gocapability/capability"
)

func CheckRequiredCapabilities(caps capability.Capabilities, reqCaps []capability.Cap) error {
	for _, c := range reqCaps {
		if !caps.Get(capability.EFFECTIVE, c) {
			return fmt.Errorf("insufficient privileges to run: missing CAP_%s", strings.ToUpper(c.String()))
		}
	}
	return nil
}

func GetSelfCapabilities() (capability.Capabilities, error) {
	selfCap, err := capability.NewPid2(0)
	if err != nil {
		return nil, err
	}
	err = selfCap.Load()
	if err != nil {
		return nil, err
	}
	return selfCap, nil
}
