package controlplane

import (
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

type Signal struct {
	ID   events.ID
	Data []trace.Argument
}

func (sig *Signal) Unmarshal(buffer []byte, dataPresentor bufferdecoder.TypeDecoder) error {
	ebpfDecoder := bufferdecoder.New(buffer, dataPresentor)
	var eventIdUint32 uint32
	err := ebpfDecoder.DecodeUint32(&eventIdUint32)
	if err != nil {
		return errfmt.Errorf("failed to decode signal event ID: %v", err)
	}

	sig.ID = events.ID(eventIdUint32)

	var argnum uint8
	err = ebpfDecoder.DecodeUint8(&argnum)
	if err != nil {
		return errfmt.Errorf("failed to decode signal argnum: %v", err)
	}

	eventDefinition := events.Core.GetDefinitionByID(sig.ID)
	if eventDefinition.NotValid() {
		return errfmt.Errorf("%d is not a valid event id", sig.ID)
	}

	evtFields := eventDefinition.GetFields()
	evtName := eventDefinition.GetName()

	sig.Data = make([]trace.Argument, len(evtFields))

	err = ebpfDecoder.DecodeArguments(sig.Data, int(argnum), evtFields, evtName, sig.ID)
	if err != nil {
		return errfmt.Errorf("failed to decode signal arguments: %v", err)
	}

	return nil
}
