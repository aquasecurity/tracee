package golang

import (
	"github.com/aquasecurity/tracee/types"
)

type noop struct {
	cb types.SignatureHandler
}

func NewNoopSignature() (types.Signature, error) {
	return &noop{}, nil
}

func (n *noop) GetMetadata() (types.SignatureMetadata, error) {
	return types.SignatureMetadata{}, nil
}

func (n *noop) GetSelectedEvents() ([]types.SignatureEventSelector, error) {
	return []types.SignatureEventSelector{}, nil
}

func (n *noop) Init(cb types.SignatureHandler) error {
	n.cb = cb
	return nil
}

func (n *noop) OnEvent(_ types.Event) error {
	// noop
	return nil
}

func (n *noop) OnSignal(_ types.Signal) error {
	return nil
}

func (n *noop) Close() {}
