package events

import "sync/atomic"

type Properties struct {
	requiredBySignature atomic.Bool
}

func (p *Properties) RequiredBySignature() bool {
	return p.requiredBySignature.Load()
}

func (p *Properties) SetRequiredBySignature(required bool) {
	p.requiredBySignature.Store(required)
}
