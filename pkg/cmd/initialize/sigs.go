package initialize

import (
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/detect"
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

		dependencies := make([]events.ID, 0)

		for _, s := range selectedEvents {
			eventID, found := events.CoreEventDefinitionGroup.GetID(s.Name)
			if !found {
				logger.Errorw("Failed to load event dependency", "event", s.Name)
				continue
			}

			dependencies = append(dependencies, eventID)
		}

		event := events.NewEvent(m.EventName, []string{"signatures", "default"}, dependencies)

		err = events.CoreEventDefinitionGroup.Add(id, event)
		if err != nil {
			logger.Errorw("Failed to add event definition", "error", err)
			continue
		}

		id++
	}
}
