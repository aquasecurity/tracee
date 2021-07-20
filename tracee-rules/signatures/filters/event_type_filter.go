package filter

import (
	"log"

	"github.com/RoaringBitmap/roaring"
	tracee "github.com/aquasecurity/tracee/tracee-ebpf/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

const ALL_EVENT_TYPES = "*"

type EventTypeFilter struct {
	signatureBitmapMatcher map[types.Event]*roaring.Bitmap
	logger                 *log.Logger
}

// CreateEventFilter Create an EventTypeFilter according to the signatures watched events types.
func CreateEventFilter(signatures []types.Signature, logger *log.Logger) (*EventTypeFilter, error) {
	eventFilter := EventTypeFilter{}
	eventFilter.logger = logger
	eventFilter.signatureBitmapMatcher = make(map[types.Event]*roaring.Bitmap)
	// Bitmap for all event types must be initialized.
	eventFilter.signatureBitmapMatcher[ALL_EVENT_TYPES] = roaring.New()

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
			if selectedEvent.Name == "" {
				selectedEvent.Name = ALL_EVENT_TYPES
			}
			if eventFilter.signatureBitmapMatcher[selectedEvent.Name] == nil {
				eventFilter.signatureBitmapMatcher[selectedEvent.Name] = roaring.New()
			}
			eventFilter.signatureBitmapMatcher[selectedEvent.Name].Add(uint32(signatureIndex))
		}
	}
	return &eventFilter, nil
}

// FilterByEvent Return a bitmap representing all the signatures that watch the given event't type
func (eventFilter *EventTypeFilter) FilterByEvent(filteredEvent types.Event) (*roaring.Bitmap, error) {
	eventBitmap := eventFilter.signatureBitmapMatcher[filteredEvent.(tracee.Event).EventName]
	allEventsBitmap := eventFilter.signatureBitmapMatcher[ALL_EVENT_TYPES]
	return roaring.Or(eventBitmap, allEventsBitmap), nil
}

func (eventFilter *EventTypeFilter) AddSignature(signature types.Signature, uid uint32) error {
	sigSelectedEvents, _ := signature.GetSelectedEvents()
	for _, selectedEvent := range sigSelectedEvents {
		if selectedEvent.Name == "" {
			selectedEvent.Name = ALL_EVENT_TYPES
		}
		eventFilter.signatureBitmapMatcher[selectedEvent.Name].Add(uid)
	}
	return nil
}

func (eventFilter *EventTypeFilter) RemoveSignature(uid uint32) error {
	for _, eventFilterBitmap := range eventFilter.signatureBitmapMatcher {
		eventFilterBitmap.Remove(uid)
	}
	return nil
}

func (eventFilter *EventTypeFilter) RemoveAllSignatures() error {
	for _, eventFilterBitmap := range eventFilter.signatureBitmapMatcher {
		eventFilterBitmap.Clear()
	}
	return nil
}
