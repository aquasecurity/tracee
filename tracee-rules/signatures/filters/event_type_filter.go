package filter

import (
	"log"

	"github.com/RoaringBitmap/roaring"
	tracee_consts "github.com/aquasecurity/tracee/tracee-ebpf/tracee"
	tracee "github.com/aquasecurity/tracee/tracee-ebpf/tracee/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

type EventTypeFilter struct {
	signatureBitmapMatcher map[types.Event]*roaring.Bitmap
	logger                 *log.Logger
}

// Create an EventTypeFilter according to the signatures watched events types.
func createEventFilter(signatures []types.Signature, logger *log.Logger) (*EventTypeFilter, error) {
	eventFilter := EventTypeFilter{}
	eventFilter.logger = logger
	eventFilter.signatureBitmapMatcher = make(map[types.Event]*roaring.Bitmap)
	for _, event := range tracee_consts.EventsIDToEvent {
		eventFilter.signatureBitmapMatcher[event.Name] = roaring.New()
	}

	// Add all signatures to the matching event filter Bitmap.
	for signatureIndex, signature := range signatures {
		meta, err := signature.GetMetadata()
		if err != nil {
			eventFilter.logger.Printf("error getting metadata: %v", err)
			continue
		}
		selectedEvents, err := signature.GetSelectedEvents()
		if err != nil {
			eventFilter.logger.Printf("error getting selected events for signature %s: %v", meta.Name, err)
			continue
		}
		for _, selectedEvent := range selectedEvents {
			if selectedEvent.Name == "*" || selectedEvent.Name == "" {
				for _, eventFilterBitmap := range eventFilter.signatureBitmapMatcher {
					eventFilterBitmap.Add(uint32(signatureIndex))
				}
			} else {
				eventFilter.signatureBitmapMatcher[selectedEvent.Name].Add(uint32(signatureIndex))
			}
		}
	}
	return &eventFilter, nil
}

// Return a bitmap representing all the signatures that watch the given event't type
func (eventFilter *EventTypeFilter) filterByEvent(filteredEvent tracee.Event) (*roaring.Bitmap, error) {
	return eventFilter.signatureBitmapMatcher[filteredEvent.EventName], nil
}

func (eventFilter *EventTypeFilter) addSignature(signature types.Signature, uid uint32) error {
	sigSelectedEvents, _ := signature.GetSelectedEvents()
	for _, selectedEvent := range sigSelectedEvents {
		eventFilter.signatureBitmapMatcher[selectedEvent.Name].Add(uid)
	}
	return nil
}

func (eventFilter *EventTypeFilter) removeSignature(uid uint32) error {
	for _, eventFilterBitmap := range eventFilter.signatureBitmapMatcher {
		eventFilterBitmap.Remove(uid)
	}
	return nil
}
