package golang

import (
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
)

type noop struct {
	cb detect.SignatureHandler
}

func NewNoopSignature() (detect.Signature, error) {
	return &noop{}, nil
}

func (n *noop) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{}, nil
}

func (n *noop) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{}, nil
}

func (n *noop) Init(ctx detect.SignatureContext) error {
	n.cb = ctx.Callback
	return nil
}

func (n *noop) OnEvent(_ protocol.Event) error {
	// noop
	return nil
}

func (n *noop) OnSignal(_ detect.Signal) error {
	return nil
}

func (n *noop) Close() {}
