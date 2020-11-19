package gosigs

// goSignature interface implementation follows

import (
	"fmt"
	"path"
	"sigengine/sigengine"
)

type ExampleSig struct {
}

func init() {

	var sig ExampleSig
	sigengine.RegisterSignature(&sig)

}

func (e *ExampleSig) GetMetadata() sigengine.SigMetadata {

	metadata := sigengine.SigMetadata{}

	metadata.Name = "example_sig"
	metadata.Description = "just an example signature"
	metadata.Authors = []string{"author_name"}
	metadata.Tags = []string{"container", "linux"}
	metadata.MitreCategory = []string{"MITRE_EXAMPLE_CATEGORY"}
	metadata.MitreSubCategory = []string{"Mitre Example sub categoryu"}

	return metadata

}

func (e *ExampleSig) GetReqEvents() []sigengine.RequestedEvent {

	eventNames := []string{"open", "execve"}

	var requestedEvents []sigengine.RequestedEvent

	for _, eventName := range eventNames {
		eventFilter := sigengine.EventFilter{Name: eventName}
		reqEvent := sigengine.RequestedEvent{Type: "tracee", EvFilter: eventFilter}
		requestedEvents = append(requestedEvents, reqEvent)
	}

	return requestedEvents

}

func (e *ExampleSig) InitSig() error {

	return nil

}

func (e *ExampleSig) OnEvent(event sigengine.Event) (sigengine.SigResult, error) {

	severity := "medium"
	match := false
	iocs := []sigengine.Ioc{}

	if traceeEvent, isOfType := event.Data.(sigengine.TraceeEvent); isOfType {

		// pid := traceeEvent.Data.ProcessID
		// returnValue := traceeEvent.Data.ReturnValue

		if traceeEvent.EventName == "open" || traceeEvent.EventName == "openat" {
			for _, arg := range traceeEvent.Args {
				if arg.Name == "pathname" {
					if val, isOfType := arg.Value.(string); isOfType && path.Base(val) == "docker.sock" {
						currentIoc := sigengine.Ioc{IocType: "event", Value: event}
						iocs = append(iocs, currentIoc)
						match = true
					}
				}
			}
		}

		result := sigengine.SigResult{Match: match, Severity: severity, Iocs: iocs}

		return result, nil

	}

	return sigengine.SigResult{}, fmt.Errorf("event is not of type sigengine.TraceeEvent")
}

func (e *ExampleSig) OnComplete() (sigengine.SigResult, error) {

	return sigengine.SigResult{}, nil

}
