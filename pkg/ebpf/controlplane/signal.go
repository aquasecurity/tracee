package controlplane

import (
	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

type signal struct {
	eventID events.ID
	args    []trace.Argument
}

func (sig *signal) Unmarshal(buffer []byte) error {
	ebpfDecoder := bufferdecoder.New(buffer)
	var eventIdUint32 uint32
	err := ebpfDecoder.DecodeUint32(&eventIdUint32)
	if err != nil {
		return errfmt.Errorf("failed to decode signal event ID: %v", err)
	}
	sig.eventID = events.ID(eventIdUint32)
	var argnum uint8
	err = ebpfDecoder.DecodeUint8(&argnum)
	if err != nil {
		return errfmt.Errorf("failed to decode signal argnum: %v", err)
	}

	eventDefinition, ok := events.CoreEventDefinitionGroup.GetSafe(sig.eventID)
	if !ok {
		return errfmt.Errorf("failed to get configuration of event %d", sig.eventID)
	}

	sig.args = make([]trace.Argument, len(eventDefinition.GetParams()))
	err = ebpfDecoder.DecodeArguments(sig.args, int(argnum), eventDefinition, sig.eventID)
	if err != nil {
		return errfmt.Errorf("failed to decode signal arguments: %v", err)
	}

	return nil
}
