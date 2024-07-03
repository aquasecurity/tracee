package policy

import "github.com/aquasecurity/tracee/pkg/utils"

// eventFlags is a struct that holds the flags for an event.
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

// eventFlagsOption is a function that sets an option on the eventFlags struct.
type eventFlagsOption func(*eventFlags)

// eventFlagsWithSubmit sets the bitmask with the policies that require
// the event to be submitted.
func eventFlagsWithSubmit(submit uint64) eventFlagsOption {
	return func(es *eventFlags) {
		es.policiesSubmit = submit
	}
}

// eventFlagsWithEmit sets the bitmask with the policies that require
// the event to be emitted.
func eventFlagsWithEmit(emit uint64) eventFlagsOption {
	return func(es *eventFlags) {
		es.policiesEmit = emit
	}
}

// eventFlagsWithEnabled sets the enabled flag.
func eventFlagsWithEnabled(enabled bool) eventFlagsOption {
	return func(es *eventFlags) {
		es.enabled = enabled
	}
}

// newEventFlags creates a new eventFlags with the given options.
// If no options are provided, the default values are used.
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

// enableSubmission sets the submit bit for the given policy Id.
func (ef *eventFlags) enableSubmission(policyId int) error {
	if !isIDInRange(policyId) {
		return PoliciesOutOfRangeError(policyId)
	}

	utils.SetBit(&ef.policiesSubmit, uint(policyId))

	return nil
}

// enableEmission sets the emit bit for the given policy Id.
func (ef *eventFlags) enableEmission(policyId int) error {
	if !isIDInRange(policyId) {
		return PoliciesOutOfRangeError(policyId)
	}

	utils.SetBit(&ef.policiesEmit, uint(policyId))

	return nil
}

// disableSubmission clears the submit bit for the given policy Id.
func (ef *eventFlags) disableSubmission(policyId int) error {
	if !isIDInRange(policyId) {
		return PoliciesOutOfRangeError(policyId)
	}

	utils.ClearBit(&ef.policiesSubmit, uint(policyId))

	return nil
}

// disableEmission clears the emit bit for the given policy Id.
func (ef *eventFlags) disableEmission(policyId int) error {
	if !isIDInRange(policyId) {
		return PoliciesOutOfRangeError(policyId)
	}

	utils.ClearBit(&ef.policiesEmit, uint(policyId))

	return nil
}

// enableEvent enables the event.
func (ef *eventFlags) enableEvent() {
	ef.enabled = true
}

// disableEvent disables the event.
func (ef *eventFlags) disableEvent() {
	ef.enabled = false
}
