package fingerprint

import (
	"errors"
	"log"

	"github.com/aquasecurity/tracee/types/trace"
)

type Fingerprint interface {
	Update(event *trace.Event)
	// Enforce(event *trace.Event) bool // Will be implemented once the enforce mode is implemented
}

type ProcessFingerprint struct {
	Cmd                           string
	FilesystemActivityFingerprint Fingerprint
	NetworkActivityFingerprint    Fingerprint
	Children                      map[string]*ProcessFingerprint
}

func NewProcessFingerprint(cmd string) *ProcessFingerprint {
	return &ProcessFingerprint{
		Cmd:                           cmd,
		FilesystemActivityFingerprint: nil, // TODO: Implement
		NetworkActivityFingerprint:    nil, // TODO: Implement
		Children:                      make(map[string]*ProcessFingerprint),
	}
}

func (processFingerprint *ProcessFingerprint) Update(event *trace.Event) {
	fingerprint, err := processFingerprint.route(event)
	if err != nil {
		log.Printf("Error updating fingerprint for incoming event: %v - %v \n", event, err)
	}

	fingerprint.Update(event)
}

// TODO: Benchmark and see if map is faster than scan
func (processFingerprint *ProcessFingerprint) route(event *trace.Event) (Fingerprint, error) {
	for _, eventSelector := range FilesystemActivityEvents {
		if eventSelector.Name == event.EventName {
			return processFingerprint.FilesystemActivityFingerprint, nil
		}
	}

	for _, eventSelector := range NetworkActivityEvents {
		if eventSelector.Name == event.EventName {
			return processFingerprint.NetworkActivityFingerprint, nil
		}
	}

	return nil, errors.New("No fingerprint found to handle the incoming event")
}

func (processFingerprint *ProcessFingerprint) AddChild(childProcessFingerprint *ProcessFingerprint) {
	processFingerprint.Children[childProcessFingerprint.Cmd] = childProcessFingerprint
}
