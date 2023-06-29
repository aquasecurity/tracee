package initialize

import (
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

func CreateEventsFromSignatures(startId events.ID, sigs []detect.Signature) {
	id := startId

	for _, s := range sigs {
		m, err := s.GetMetadata()
		if err != nil {
			logger.Errorw("Failed to load event", "error", err)
			continue
		}

		selectedEvents, err := s.GetSelectedEvents()
		if err != nil {
			logger.Errorw("Failed to load event", "error", err)
			continue
		}

		evtDependency := make([]events.ID, 0)

		for _, s := range selectedEvents {
			eventID, found := events.Core.GetEventIDByName(s.Name)
			if !found {
				logger.Errorw("Failed to load event dependency", "event", s.Name)
				continue
			}

			evtDependency = append(evtDependency, eventID)
		}

		event := events.NewEvent(
			id,                                // id,
			events.Sys32Undefined,             // id32
			m.EventName,                       // eventName
			"",                                // docPath
			false,                             // internal
			false,                             // syscall
			[]string{"signatures", "default"}, // sets
			events.NewDependencies(
				evtDependency, // ids
				nil,           // probes
				nil,           // ksyms
				nil,           // tailcalls
				nil,           // capabilities
			),
			[]trace.ArgMeta{},
		)

		err = events.Core.Add(id, event)
		if err != nil {
			logger.Errorw("Failed to add event definition", "error", err)
			continue
		}

		id++
	}
}
