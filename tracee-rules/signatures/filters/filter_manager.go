package filter

import (
	"log"

	"github.com/RoaringBitmap/roaring"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

type FilterManager struct {
	registeredFilters []Filter
	signaturesIndex   map[int]types.Signature
	logger            *log.Logger
	removedSigs       []int
}

// Initialize the manager with all the filters.
func NewFilterManager(logger *log.Logger, signatures []types.Signature) (*FilterManager, error) {
	filterManager := FilterManager{}
	filterManager.signaturesIndex = make(map[int]types.Signature)
	for i, signature := range signatures {
		filterManager.signaturesIndex[i] = signature
	}
	filterManager.logger = logger
	eventFilter, _ := createEventFilter(signatures, logger)
	filterManager.registeredFilters = append(filterManager.registeredFilters, eventFilter)
	return &filterManager, nil
}

// Get all the signatures that the event given is relevant for them.
func (filterManager *FilterManager) getFilteredSignaturesCannels(event types.Event) ([]types.Signature, error) {
	matchingSignaturesBitmap := roaring.New()
	for i, filter := range filterManager.registeredFilters {
		filteredSignatures, _ := filter.filterByEvent(event)
		if i == 0 {
			matchingSignaturesBitmap.Or(filteredSignatures)
		} else {
			matchingSignaturesBitmap.And(filteredSignatures)
		}
	}
	matchingSignatures := make([]types.Signature, 0)
	eventChannelIndexIterator := matchingSignaturesBitmap.Iterator()
	for eventChannelIndexIterator.HasNext() {
		matchingSignatures = append(matchingSignatures, filterManager.signaturesIndex[int(eventChannelIndexIterator.Next())])
	}
	return matchingSignatures, nil
}
