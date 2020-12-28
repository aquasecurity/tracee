package signaturestest

import "github.com/aquasecurity/tracee/tracee-rules/types"

// SigTest is a utility to test signatures
type SigTest struct {
	// Events are a series of events that the signature will be tested with (in the provided order)
	Events []types.Event
	// CB provide a callback for this test case only if you want to check the Finding result
	// if providing your own callback, make sure to call SetStatus from it
	CB types.SignatureHandler
	// Expect declares if we expect the signature to match for this event
	Expect bool
	// Status shows if the signatures has matched
	Status bool
}

func (st *SigTest) Init(sig types.Signature) {
	st.Status = false
	if st.CB != nil {
		sig.Init(func(res types.Finding) {
			st.SetStatus(res)
			st.CB(res)
		})
	} else {
		sig.Init(st.SetStatus)
	}
}

func (st *SigTest) SetStatus(res types.Finding) {
	st.Status = true
}
