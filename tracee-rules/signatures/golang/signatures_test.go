package main

import "github.com/aquasecurity/tracee/tracee-rules/types"

// sigTest is a utility to test signatures
type sigTest struct {
	// events are a series of events that the signature will be tested with (in the provided order)
	events []types.Event
	// provide a callback for this test case only if you want to check the Finding result
	// if providing your own callback, make sure to call setStatus from it
	cb types.SignatureHandler
	// expect declares if we expect the signature to match for this event
	expect bool
	// status shows if the signatures has mathced
	status bool
}

func (st *sigTest) init(sig types.Signature) {
	st.status = false
	if st.cb != nil {
		sig.Init(st.cb)
	} else {
		sig.Init(st.setStatus)
	}
}

func (st *sigTest) setStatus(res types.Finding) {
	st.status = true
}
