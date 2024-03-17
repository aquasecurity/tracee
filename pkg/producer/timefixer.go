package producer

// A decorator producer that is responsible to fix events timestamps so they
// will match the ones received from the kernel.
// In practice, it means changing all times from being since epoch to monotonic
// times (since boot).
type TimeFixerProducer struct {
	internalProducer EventsProducer
	bootTime         uint64
}

func initTimeFixerProducer(producer EventsProducer) *TimeFixerProducer {
	return &TimeFixerProducer{
		internalProdcer: producer,
	}
}

func (tfixer *TimeFixerProducer) Produce() (trace.Event, error) {
	event, err := internalProducer.Produce()
	if err != nil {
		return trace.Event{}, nil
	}
	switch event.ID {
	case events.InitTraceeData:
		tfixer.bootTime = parse.ArgVal[uint64](event.Args, "boot_time")
	default:
		event.Timestamp -= tfixer.bootTime
	}
	return event, nil
}

func (tfixer *TimeFixerProducer) Done() <-chan struct{} {
	return tfixer.internalProducer.Done()
}
