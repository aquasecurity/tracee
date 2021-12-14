package capabilities

import (
	"fmt"
	"github.com/syndtr/gocapability/capability"
)

func CheckRequiredCapabilities(caps capability.Capabilities) error {
	if !caps.Get(capability.EFFECTIVE, capability.CAP_SYS_ADMIN) {
		return fmt.Errorf("insufficient privileges to run: missing CAP_SYS_ADMIN")
	}
	if !caps.Get(capability.EFFECTIVE, capability.CAP_IPC_LOCK) {
		return fmt.Errorf("insufficient privileges to run: missing CAP_IPC_LOCK")
	}
	return nil
}

func SelfCapabilities() (capability.Capabilities, error) {
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
