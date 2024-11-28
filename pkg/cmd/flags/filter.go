package flags

import (
	"strings"

	"github.com/aquasecurity/tracee/pkg/events"
)

type eventFilter struct {
	Equal    []string
	NotEqual []string
}

func prepareEventsToTrace(eventFilter eventFilter, eventsNameToID map[string]events.ID) (map[events.ID]string, error) {
	eventsToTrace := eventFilter.Equal
	excludeEvents := eventFilter.NotEqual
	var setsToTrace []string

	var idToName map[events.ID]string
	setsToEvents := make(map[string][]events.ID)
	isExcluded := make(map[events.ID]bool)

	// build a map: k:set, v:eventID
	for _, eventDefinition := range events.Core.GetDefinitions() {
		for _, set := range eventDefinition.GetSets() {
			setsToEvents[set] = append(setsToEvents[set], eventDefinition.GetID())
		}
	}

	// mark excluded events (isExcluded) by their id
	for _, name := range excludeEvents {
		if strings.HasSuffix(name, "*") { // handle event prefixes with wildcards
			found := false
			prefix := name[:len(name)-1]
			for event, id := range eventsNameToID {
				if strings.HasPrefix(event, prefix) {
					isExcluded[id] = true
					found = true
				}
			}
			if !found {
				return nil, InvalidEventExcludeError(name)
			}
		} else {
			id, ok := eventsNameToID[name]
			if !ok {
				return nil, InvalidEventExcludeError(name)
			}
			isExcluded[id] = true
		}
	}

	// if no events were specified, add all events from the default set
	if len(eventsToTrace) == 0 {
		setsToTrace = append(setsToTrace, "default")
	}

	// build a map: k:eventID, v:eventName with all events to trace
	idToName = make(map[events.ID]string, events.Core.Length())
	for _, name := range eventsToTrace {
		if strings.HasSuffix(name, "*") { // handle event prefixes with wildcards
			found := false
			prefix := name[:len(name)-1]
			for event, id := range eventsNameToID {
				if strings.HasPrefix(event, prefix) && !isExcluded[id] {
					idToName[id] = event
					found = true
				}
			}
			if !found {
				return nil, InvalidEventError(name)
			}
		} else {
			id, ok := eventsNameToID[name]
			if !ok {
				// no matching event - maybe it is actually a set?
				if _, ok = setsToEvents[name]; ok {
					setsToTrace = append(setsToTrace, name)
					continue
				}
				return nil, InvalidEventError(name)
			}
			idToName[id] = name
		}
	}

	// add events from sets to the map containing events to trace
	for _, set := range setsToTrace {
		setEvents := setsToEvents[set]
		for _, id := range setEvents {
			if !isExcluded[id] {
				idToName[id] = events.Core.GetDefinitionByID(id).GetName()
			}
		}
	}

	return idToName, nil
}
