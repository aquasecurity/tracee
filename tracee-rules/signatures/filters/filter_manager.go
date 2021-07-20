package filter

import (
	"fmt"
	"log"

	"github.com/RoaringBitmap/roaring"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

type FilterManager struct {
	registeredFilters  []Filter
	signaturesIndex    map[int]types.Signature
	logger             *log.Logger
	freeSignaturesUIDs []int
}

// NewFilterManager Initialize the manager with all the filters.
func NewFilterManager(logger *log.Logger, signatures []types.Signature) (*FilterManager, error) {
	filterManager := FilterManager{}
	filterManager.signaturesIndex = make(map[int]types.Signature)
	for i, signature := range signatures {
		filterManager.signaturesIndex[i] = signature
	}
	filterManager.logger = logger
	eventFilter, _ := CreateEventFilter(signatures, logger)
	filterManager.registeredFilters = append(filterManager.registeredFilters, eventFilter)
	return &filterManager, nil
}

// GetFilteredSignatures Get all the signatures that the event given is relevant for them.
func (filterManager *FilterManager) GetFilteredSignatures(event types.Event) ([]types.Signature, error) {
	matchingSignaturesBitmap := roaring.New()
	for i, filter := range filterManager.registeredFilters {
		filteredSignatures, _ := filter.FilterByEvent(event)
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

// AddSignature Generate the new signature a new UID and add it to all the filters.
func (filterManager *FilterManager) AddSignature(signature types.Signature) error {
	newSignatureId := 0
	if len(filterManager.freeSignaturesUIDs) == 0 {
		newSignatureId = len(filterManager.signaturesIndex)
	} else {
		newSignatureId = filterManager.freeSignaturesUIDs[0]
		filterManager.freeSignaturesUIDs = filterManager.freeSignaturesUIDs[1:]
	}
	filterManager.signaturesIndex[newSignatureId] = signature
	for _, filter := range filterManager.registeredFilters {
		err := filter.AddSignature(signature, uint32(newSignatureId))
		if err != nil {
			filterManager.logger.Printf("Error while adding signature - %v", err)
		}
	}
	return nil
}

// RemoveSignature Remove the signature from all filters and free its UID.
func (filterManager *FilterManager) RemoveSignature(signature types.Signature) error {
	signatureToRemoveId := -1
	for i, sig := range filterManager.signaturesIndex {
		if signature == sig {
			signatureToRemoveId = i
			break
		}
	}
	if signatureToRemoveId == -1 {
		signatureMetaData, _ := signature.GetMetadata()
		return fmt.Errorf("Error removing signature from filters - no matching signature found with ID %+v", signatureMetaData)
	}
	for _, filter := range filterManager.registeredFilters {
		filter.RemoveSignature(uint32(signatureToRemoveId))
	}
	delete(filterManager.signaturesIndex, signatureToRemoveId)
	filterManager.freeSignaturesUIDs = append(filterManager.freeSignaturesUIDs, signatureToRemoveId)
	return nil
}

// RemoveAllSignatures Remove all signatures registered from all filters registered.
func (filterManager *FilterManager) RemoveAllSignatures() error {
	for _, filter := range filterManager.registeredFilters {
		filter.RemoveAllSignatures()
	}
	return nil
}
