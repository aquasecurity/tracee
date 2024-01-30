package controlplane

import (
	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/extensions"
	"github.com/aquasecurity/tracee/types/trace"
)

type signal struct {
	id   int
	args []trace.Argument
}

func (sig *signal) Unmarshal(buffer []byte) error {
	ebpfDecoder := bufferdecoder.New(buffer)
	var eventIdUint32 uint32
	err := ebpfDecoder.DecodeUint32(&eventIdUint32)
	if err != nil {
		return errfmt.Errorf("failed to decode signal event ID: %v", err)
	}
	sig.id = int(eventIdUint32)
	var argnum uint8
	err = ebpfDecoder.DecodeUint8(&argnum)
	if err != nil {
		return errfmt.Errorf("failed to decode signal argnum: %v", err)
	}

	if !extensions.Definitions.IsDefinedInAny(sig.id) {
		return errfmt.Errorf("failed to get event %d configuration", sig.id)
	}
	eventDefinition := extensions.Definitions.GetByIDFromAny(sig.id)
	sig.args = make([]trace.Argument, len(eventDefinition.GetParams()))
	err = ebpfDecoder.DecodeArguments(sig.args, int(argnum), eventDefinition, sig.id)
	if err != nil {
		return errfmt.Errorf("failed to decode signal arguments: %v", err)
	}

	return nil
}
