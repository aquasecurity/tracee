package filter

import (
	"fmt"
	"log"
	"sync"

	"github.com/RoaringBitmap/roaring"
	tracee "github.com/aquasecurity/tracee/tracee-ebpf/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

const ALL_EVENT_TYPES = "*"

type EventTypeFilter struct {
	signatureBitmapMatcher   map[string]*roaring.Bitmap // Map between signature type to the matching signatures bitmap.
	logger                   *log.Logger
	registeredSignatures     map[uint32]bool // Each registered signature's signatureID point to true.
	signatureOperationsMutex sync.Mutex
}

// CreateEventFilter Create an EventTypeFilter according to the signatures received, building bitmaps to filter
// signatures to be called upon received event according to the event types selected by each signature.
func CreateEventFilter(signatures []types.Signature, logger *log.Logger) (*EventTypeFilter, error) {
	eventFilter := EventTypeFilter{}
	eventFilter.logger = logger
	eventFilter.signatureOperationsMutex.Lock()
	eventFilter.signatureBitmapMatcher = make(map[string]*roaring.Bitmap)
	eventFilter.registeredSignatures = make(map[uint32]bool)

	// Bitmap for all event types must be initialized.
	eventFilter.signatureBitmapMatcher[ALL_EVENT_TYPES] = roaring.New()
	eventFilter.signatureOperationsMutex.Unlock()
	// Add all signatures to the matching event filter Bitmap.
	for signatureIndex, signature := range signatures {
		err := eventFilter.AddSignature(signature, uint32(signatureIndex))
		if err != nil {
			logger.Println(err)
		}
	}
	return &eventFilter, nil
}

// FilterByEvent Return a bitmap representing all the signatures that watch the given event's type
func (eventFilter *EventTypeFilter) FilterByEvent(filteredEvent types.Event) (*roaring.Bitmap, error) {
	eventFilter.signatureOperationsMutex.Lock()
	defer eventFilter.signatureOperationsMutex.Unlock()
	eventBitmap := eventFilter.signatureBitmapMatcher[filteredEvent.(tracee.Event).EventName]
	if eventBitmap == nil {
		eventBitmap = roaring.New()
	}
	allEventsBitmap := eventFilter.signatureBitmapMatcher[ALL_EVENT_TYPES]
	return roaring.Or(eventBitmap, allEventsBitmap), nil
}

func (eventFilter *EventTypeFilter) AddSignature(signature types.Signature, signatureID uint32) error {
	meta, err := signature.GetMetadata()
	if err != nil {
		return fmt.Errorf("error getting metadata: %v", err)
	}
	eventFilter.signatureOperationsMutex.Lock()
	defer eventFilter.signatureOperationsMutex.Unlock()
	if _, isKeyExist := eventFilter.registeredSignatures[signatureID]; isKeyExist == true {
		return fmt.Errorf("error registering signature %s to EventTypeFilter: given signature signatureID (%d) is already taken", meta.Name, signatureID)
	}
	sigSelectedEvents, err := signature.GetSelectedEvents()
	if err != nil {
		return fmt.Errorf("error getting selected events for signature %s: %v", meta.Name, err)
	}
	for _, selectedEvent := range sigSelectedEvents {
		if selectedEvent.Name == "" {
			selectedEvent.Name = ALL_EVENT_TYPES
		}
		if eventFilter.signatureBitmapMatcher[selectedEvent.Name] == nil {
			eventFilter.signatureBitmapMatcher[selectedEvent.Name] = roaring.New()
		}
		eventFilter.signatureBitmapMatcher[selectedEvent.Name].Add(signatureID)
	}
	eventFilter.registeredSignatures[signatureID] = true
	return nil
}

func (eventFilter *EventTypeFilter) RemoveSignature(signatureID uint32) error {
	eventFilter.signatureOperationsMutex.Lock()
	defer eventFilter.signatureOperationsMutex.Unlock()
	if eventFilter.registeredSignatures[signatureID] == false {
		return fmt.Errorf("error removing signature with signatureID %d: no matching signature's signatureID exist", signatureID)
	}
	for _, eventFilterBitmap := range eventFilter.signatureBitmapMatcher {
		eventFilterBitmap.Remove(signatureID)
	}
	delete(eventFilter.registeredSignatures, signatureID)
	return nil
}

func (eventFilter *EventTypeFilter) RemoveAllSignatures() error {
	eventFilter.signatureOperationsMutex.Lock()
	defer eventFilter.signatureOperationsMutex.Unlock()
	for _, eventFilterBitmap := range eventFilter.signatureBitmapMatcher {
		eventFilterBitmap.Clear()
	}
	return nil
}
