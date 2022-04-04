package ebpf

import (
	"github.com/syndtr/gocapability/capability"
)

func GetCapabilitiesRequiredByEvents(events []int32) []capability.Cap {
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

func addEventAndDependenciesCapabilities(event int32, reqCapabilities map[capability.Cap]bool) {
	eDef, ok := EventsDefinitions[event]
	if !ok {
		return
	}
	for _, reqCap := range eDef.Dependencies.capabilities {
		reqCapabilities[reqCap] = true
	}
	if len(eDef.Dependencies.ksymbols) > 0 {
		reqCapabilities[capability.CAP_SYSLOG] = true
	}

	for _, d := range eDef.Dependencies.events {
		addEventAndDependenciesCapabilities(d.eventID, reqCapabilities)
	}
}
