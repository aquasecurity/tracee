package events

import (
	"github.com/syndtr/gocapability/capability"
)

func RequiredCapabilities(events []ID) []capability.Cap {
	reqCapabilities := make(map[capability.Cap]bool)
	for _, e := range events {
		addEventAndDependenciesCapabilities(e, reqCapabilities)
	}

	capList := make([]capability.Cap, len(reqCapabilities))
	i := 0
	for reqCap := range reqCapabilities {
		capList[i] = reqCap
		i++
	}
	return capList
}

func addEventAndDependenciesCapabilities(event ID, reqCapabilities map[capability.Cap]bool) {
	eDef, ok := Definitions.GetSafe(event)
	if !ok {
		return
	}
	for _, reqCap := range eDef.Dependencies.Capabilities {
		reqCapabilities[reqCap] = true
	}
	if len(eDef.Dependencies.KSymbols) > 0 {
		reqCapabilities[capability.CAP_SYSLOG] = true
	}

	for _, d := range eDef.Dependencies.Events {
		addEventAndDependenciesCapabilities(d.EventID, reqCapabilities)
	}
}
