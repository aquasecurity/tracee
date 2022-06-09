package events

import (
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

func RequiredCapabilities(events []ID) []cap.Value {
	reqCapabilities := make(map[cap.Value]bool)
	for _, e := range events {
		addEventAndDependenciesCapabilities(e, reqCapabilities)
	}

	capList := make([]cap.Value, len(reqCapabilities))
	i := 0
	for reqCap := range reqCapabilities {
		capList[i] = reqCap
		i++
	}
	return capList
}

func addEventAndDependenciesCapabilities(event ID, reqCapabilities map[cap.Value]bool) {
	eDef, ok := Definitions.GetSafe(event)
	if !ok {
		return
	}
	for _, reqCap := range eDef.Dependencies.Capabilities {
		reqCapabilities[reqCap] = true
	}
	if len(eDef.Dependencies.KSymbols) > 0 {
		reqCapabilities[cap.SYSLOG] = true
	}

	for _, d := range eDef.Dependencies.Events {
		addEventAndDependenciesCapabilities(d.EventID, reqCapabilities)
	}
}
