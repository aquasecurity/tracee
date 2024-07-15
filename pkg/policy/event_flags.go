package policy

import "github.com/aquasecurity/tracee/pkg/utils"

// eventFlags is a struct that holds the flags of an event.
type eventFlags struct {
	// policiesSubmit is a bitmask with the policies that require the event,
	// if matched, to be submitted to the userland from the ebpf program.
	// It is computed on policies updates.
	policiesSubmit uint64

	// policiesEmit is a bitmask with the policies that require the event,
	// if matched, to be emitted in the pipeline sink stage.
	// It is computed on policies updates.
	policiesEmit uint64

	// enabled indicates if the event is enabled.
	// It is *NOT* computed on policies updates, so its value remains the same
	// until changed via the API.
	enabled bool
}

//
// constructor
//

type eventFlagsOption func(*eventFlags)

func eventFlagsWithSubmit(submit uint64) eventFlagsOption {
	return func(es *eventFlags) {
		es.policiesSubmit = submit
	}
}

func eventFlagsWithEmit(emit uint64) eventFlagsOption {
	return func(es *eventFlags) {
		es.policiesEmit = emit
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
		policiesSubmit: 0,
		policiesEmit:   0,
		enabled:        false,
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

func (ef *eventFlags) enableSubmission(policyId int) {
	utils.SetBit(&ef.policiesSubmit, uint(policyId))
}

func (ef *eventFlags) enableEmission(policyId int) {
	utils.SetBit(&ef.policiesEmit, uint(policyId))
}

func (ef *eventFlags) disableSubmission(policyId int) {
	utils.ClearBit(&ef.policiesSubmit, uint(policyId))
}

func (ef *eventFlags) disableEmission(policyId int) {
	utils.ClearBit(&ef.policiesEmit, uint(policyId))
}

func (ef *eventFlags) enableEvent() {
	ef.enabled = true
}

func (ef *eventFlags) disableEvent() {
	ef.enabled = false
}
