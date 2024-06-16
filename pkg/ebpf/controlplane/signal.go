package controlplane

import (
	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

type signal struct {
	id   events.ID
	args []trace.Argument
}

func (sig *signal) Unmarshal(buffer []byte) error {
	ebpfDecoder := bufferdecoder.New(buffer)
	var eventIdUint32 uint32
	err := ebpfDecoder.DecodeUint32(&eventIdUint32)
	if err != nil {
		return errfmt.Errorf("failed to decode signal event ID: %v", err)
	}
	sig.id = events.ID(eventIdUint32)
	var argnum uint8
	err = ebpfDecoder.DecodeUint8(&argnum)
	if err != nil {
		return errfmt.Errorf("failed to decode signal argnum: %v", err)
	}

	if !events.Core.IsDefined(sig.id) {
		return errfmt.Errorf("failed to get event %d configuration", sig.id)
	}
	eventDefinition := events.Core.GetDefinitionByID(sig.id)
	evtParams := eventDefinition.GetParams()
	evtName := eventDefinition.GetName()
	sig.args = make([]trace.Argument, len(evtParams))
	err = ebpfDecoder.DecodeArguments(sig.args, int(argnum), evtParams, evtName, sig.id)
	if err != nil {
		return errfmt.Errorf("failed to decode signal arguments: %v", err)
	}

	return nil
}
