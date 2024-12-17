package policy

import "github.com/aquasecurity/tracee/pkg/utils"

// eventFlags is a struct that holds the flags of an event.
type eventFlags struct {
	// rulesToSubmit is a bitmap with the policies that require the event,
	// if matched, to be submitted to the userland from the ebpf program.
	// It is computed on policies updates.
	rulesToSubmit uint64

	// rulesToEmit is a bitmask with the policies that require the event,
	// if matched, to be emitted in the pipeline sink stage.
	// It is computed on policies updates.
	rulesToEmit uint64

	// requiredBySignature indicates if the event is required by a signature event.
	requiredBySignature bool

	// enabled indicates if the event is enabled.
	// It is *NOT* computed on policies updates, so its value remains the same
	// until changed via the API.
	enabled bool

	// TODO: consider adding rules version here - this value will be taken from here when populating events config map, just like rulesToSubmit
	rulesVersion uint8
	// Question: should rulesVersion be under per-event config (map in bpf) - if so, where is it being populated?
	// TODO: consider moving above requiredBySignature and enabled to be under the same place where we put rulesVersion
}

//
// constructor
//

type eventFlagsOption func(*eventFlags)

func eventFlagsWithSubmit(submit uint64) eventFlagsOption {
	return func(es *eventFlags) {
		es.rulesToSubmit = submit
	}
}

func eventFlagsWithEmit(emit uint64) eventFlagsOption {
	return func(es *eventFlags) {
		es.rulesToEmit = emit
	}
}

func eventFlagsWithRequiredBySignature(required bool) eventFlagsOption {
	return func(es *eventFlags) {
		es.requiredBySignature = required
	}
}

func eventFlagsWithEnabled(enabled bool) eventFlagsOption {
	return func(es *eventFlags) {
		es.enabled = enabled
	}
}

func newEventFlags(options ...eventFlagsOption) *eventFlags {
	// default values
	ef := &eventFlags{
		rulesToSubmit:      0,
		rulesToEmit:        0,
		requiredBySignature: false,
		enabled:             false,
	}

	// apply options
	for _, option := range options {
		option(ef)
	}

	return ef
}

//
// methods
//

func (ef *eventFlags) enableSubmission(ruleId int) {
	utils.SetBit(&ef.rulesToSubmit, uint(ruleId))
}

func (ef *eventFlags) enableEmission(ruleId int) {
	utils.SetBit(&ef.rulesToEmit, uint(ruleId))
}

func (ef *eventFlags) disableSubmission(ruleId int) {
	utils.ClearBit(&ef.rulesToSubmit, uint(ruleId))
}

func (ef *eventFlags) disableEmission(ruleId int) {
	utils.ClearBit(&ef.rulesToEmit, uint(ruleId))
}

func (ef *eventFlags) enableEvent() {
	ef.enabled = true
}

func (ef *eventFlags) disableEvent() {
	ef.enabled = false
}
