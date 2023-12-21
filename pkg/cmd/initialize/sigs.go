package initialize

import (
	"strconv"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils/set"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

func CreateEventsFromSignatures(startId events.ID, sigs []detect.Signature) map[string]int32 {
	newEventDefID := startId
	res := make(map[string]int32)
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
			if s.Source != "tracee" {
				// A legacy solution we supported was for external sources to push events
				// into signatures. They would declare their source to be a different name instead
				// of  "tracee".
				// As such, actual event dependencies should only be sourced from "tracee" selectors.
				continue
			}
			eventDefID, found := events.Core.GetDefinitionIDByName(s.Name)
			if !found {
				logger.Errorw("Failed to load event dependency", "event", s.Name)
				continue
			}

			evtDependency = append(evtDependency, eventDefID)
		}

		tags := set.New[string](append([]string{"signatures", "default"}, m.Tags...)...)

		version, err := events.NewVersionFromString(m.Version)
		// if the version is not valid semver, set it to 1.0.X,
		// where X is either 0 or the version number from the signature
		if err != nil {
			var x uint64

			if m.Version != "" {
				n, _ := strconv.Atoi(m.Version)
				// if there is an error, n is 0, setting the version to 1.0.0
				x = uint64(n)
			}

			version = events.NewVersion(1, 0, x)
		}

		properties := map[string]interface{}{
			"signatureName": m.Name,
			"signatureID":   m.ID,
		}

		for k, v := range m.Properties {
			properties[k] = v
		}

		newEventDef := events.NewDefinition(
			newEventDefID,         // id,
			events.Sys32Undefined, // id32
			m.EventName,           // eventName
			version,               // version
			m.Description,         // description
			"",                    // docPath
			false,                 // internal
			false,                 // syscall
			tags.Items(),          // tags
			events.NewDependencies(
				evtDependency,
				[]events.KSymbol{},
				[]events.Probe{},
				[]events.TailCall{},
				events.Capabilities{},
			),
			[]trace.ArgMeta{},
			properties,
		)

		err = events.Core.Add(newEventDefID, newEventDef)
		if err != nil {
			logger.Errorw("Failed to add event definition", "error", err)
			continue
		}

		res[m.EventName] = int32(newEventDefID)
		newEventDefID++
	}
	return res
}
