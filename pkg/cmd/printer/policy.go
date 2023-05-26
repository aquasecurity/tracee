package printer

import (
	"sync"

	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/metrics"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/types/trace"
)

// PolicyEventPrinter is an EventPrinter that prints events based on a policy
// Each policy can define a global action or action per events.
// A map is created between policy:event or policy to printerName
// which is used to send events to the correct printer
type PolicyEventPrinter struct {
	printerConfigs []Config
	policies       []policy.PolicyFile
	printers       []EventPrinter
	numOfPrinters  int
	printerMap     map[string]chan trace.Event
	eventsMap      map[string]chan trace.Event
	wg             *sync.WaitGroup
	done           chan struct{}
	containerMode  ContainerMode
}

// NewPolicyEventPrinter creates a new PolicyEventPrinter
func NewPolicyEventPrinter(pConfigs []Config, policies []policy.PolicyFile, containerMode ContainerMode) (*PolicyEventPrinter, error) {
	p := &PolicyEventPrinter{
		printerConfigs: pConfigs,
		policies:       policies,
		containerMode:  containerMode,
	}
	return p, p.Init()
}

// Init serves as the initializer method for every event Printer type
func (pp *PolicyEventPrinter) Init() error {
	printerMap := make(map[string]chan trace.Event)
	done := make(chan struct{})
	wg := &sync.WaitGroup{}

	printers := make([]EventPrinter, 0, len(pp.printerConfigs))
	for _, pConfig := range pp.printerConfigs {
		pConfig.ContainerMode = pp.containerMode

		p, err := New(pConfig)
		if err != nil {
			return err
		}

		err = p.Init()
		if err != nil {
			return err
		}

		printers = append(printers, p)

		eventChan := make(chan trace.Event, 1000)
		wg.Add(1)
		go startPrinter(wg, done, eventChan, p)

		printerName := pConfig.Kind + ":" + pConfig.OutPath
		printerMap[printerName] = eventChan
	}

	eventsMap := pp.createEventMap(printerMap)

	pp.printerMap = printerMap
	pp.eventsMap = eventsMap
	pp.wg = wg
	pp.printers = printers
	pp.numOfPrinters = len(printers)
	pp.done = done

	return nil
}

// Preamble prints something before event printing begins (one time)
func (pp *PolicyEventPrinter) Preamble() {
	for _, printer := range pp.printers {
		printer.Preamble()
	}
}

// Epilogue prints something after event printing ends (one time)
func (pp *PolicyEventPrinter) Epilogue(stats metrics.Stats) {
	// if you execute epilogue no other events should be sent to the printers,
	// so we finish the events goroutines
	close(pp.done)

	pp.wg.Wait()
	for _, printer := range pp.printers {
		printer.Epilogue(stats)
	}
}

// Print prints a single event
func (pp *PolicyEventPrinter) Print(event trace.Event) {
	executed := make(map[chan trace.Event]bool, 0)

	var printersExecuted int
	for _, policyName := range event.MatchedPoliciesNames {
		if printersExecuted == pp.numOfPrinters {
			return
		}

		key := policyName + ":" + event.EventName

		c, ok := pp.eventsMap[key]
		if !ok {
			logger.Debugw("printers not found for event", "event", event)
			continue
		}

		// avoid executing the same printer twice
		if _, ok := executed[c]; ok {
			continue
		}

		c <- event

		printersExecuted++
		executed[c] = true
	}
}

// dispose of resources
func (pp *PolicyEventPrinter) Close() {
	for _, printer := range pp.printers {
		printer.Close()
	}
}

func (pp *PolicyEventPrinter) createEventMap(printerMap map[string]chan trace.Event) map[string]chan trace.Event {
	eventsMap := make(map[string]chan trace.Event)

	for _, p := range pp.policies {
		for _, rule := range p.Rules {
			key := p.Name + ":" + rule.Event

			action := getAction(p.DefaultAction)
			c, ok := printerMap[action]
			if !ok {
				logger.Fatalw("printer not found", "printerName", action)
			}

			eventsMap[key] = c

			// if no specific action is defined for this event, move on
			if rule.Action == "" {
				continue
			}

			action = getAction(rule.Action)
			c, ok = printerMap[action]
			if !ok {
				logger.Fatalw("printer not found", "printerName", action)
			}

			eventsMap[key] = c
		}
	}

	return eventsMap
}

func getAction(action string) string {
	if action == "log" {
		return "json:stdout"
	}
	return action
}
