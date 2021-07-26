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
	registeredSignatures     map[uint32]bool // Each registered signature's UID point to true.
	signatureOperationsMutex sync.Mutex
}

// CreateEventFilter Create an EventTypeFilter according to the signatures received, building bitmaps to filter
// signatures to be called upon received event according to the event types selected by each signature.
func CreateEventFilter(signatures []types.Signature, logger *log.Logger) (*EventTypeFilter, error) {
	eventFilter := EventTypeFilter{}
	eventFilter.logger = logger
	eventFilter.signatureOperationsMutex.Lock()
	defer eventFilter.signatureOperationsMutex.Unlock()
	eventFilter.signatureBitmapMatcher = make(map[string]*roaring.Bitmap)
	eventFilter.registeredSignatures = make(map[uint32]bool)

	// Bitmap for all event types must be initialized.
	eventFilter.signatureBitmapMatcher[ALL_EVENT_TYPES] = roaring.New()
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

func (eventFilter *EventTypeFilter) AddSignature(signature types.Signature, uid uint32) error {
	meta, err := signature.GetMetadata()
	if err != nil {
		return fmt.Errorf("error getting metadata: %v", err)
	}
	eventFilter.signatureOperationsMutex.Lock()
	defer eventFilter.signatureOperationsMutex.Unlock()
	if _, isKeyExist := eventFilter.registeredSignatures[uid]; isKeyExist == true {
		return fmt.Errorf("error registering signature %s to EventTypeFilter: given signature UID (%d) is already taken", meta.Name, uid)
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
		eventFilter.signatureBitmapMatcher[selectedEvent.Name].Add(uid)
	}
	eventFilter.registeredSignatures[uid] = true
	return nil
}

func (eventFilter *EventTypeFilter) RemoveSignature(uid uint32) error {
	eventFilter.signatureOperationsMutex.Lock()
	defer eventFilter.signatureOperationsMutex.Unlock()
	if eventFilter.registeredSignatures[uid] == false {
		return fmt.Errorf("error removing signature with UID %d: no matching signature's UID exist", uid)
	}
	for _, eventFilterBitmap := range eventFilter.signatureBitmapMatcher {
		eventFilterBitmap.Remove(uid)
	}
	delete(eventFilter.registeredSignatures, uid)
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
