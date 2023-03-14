package signature

import (
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
)

// FakeSignature is a mock for the detect.Signature interface,
// it allows customization of methods through the fields.
// It can be used for tests.
type FakeSignature struct {
	FakeGetMetadata       func() (detect.SignatureMetadata, error)
	FakeGetSelectedEvents func() ([]detect.SignatureEventSelector, error)
	FakeInit              func(detect.SignatureContext) error
	FakeOnEvent           func(protocol.Event) error
	FakeOnSignal          func(signal detect.Signal) error
}

func (fs FakeSignature) GetMetadata() (detect.SignatureMetadata, error) {
	if fs.FakeGetMetadata != nil {
		return fs.FakeGetMetadata()
	}

	return detect.SignatureMetadata{
		ID:   "TRC-FAKE",
		Name: "Fake Signature",
	}, nil
}

func (fs FakeSignature) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	if fs.FakeGetSelectedEvents != nil {
		return fs.FakeGetSelectedEvents()
	}
	return []detect.SignatureEventSelector{}, nil
}

func (fs FakeSignature) Init(ctx detect.SignatureContext) error {
	if fs.FakeInit != nil {
		return fs.FakeInit(ctx)
	}
	return nil
}

func (fs FakeSignature) OnEvent(event protocol.Event) error {
	if fs.FakeOnEvent != nil {
		return fs.FakeOnEvent(event)
	}
	return nil
}

func (fs FakeSignature) OnSignal(signal detect.Signal) error {
	if fs.FakeOnSignal != nil {
		return fs.FakeOnSignal(signal)
	}
	return nil
}

func (fs *FakeSignature) Close() {}
