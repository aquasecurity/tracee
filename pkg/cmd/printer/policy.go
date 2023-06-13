package printer

import (
	"fmt"
	"sync"

	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/errfmt"
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
	printerConfigs []config.PrinterConfig
	policies       []policy.PolicyFile
	printers       []EventPrinter
	numOfPrinters  int
	printerMap     map[string][]chan trace.Event
	eventsMap      map[string]string
	wg             *sync.WaitGroup
	done           chan struct{}
	containerMode  config.ContainerMode
}

// NewPolicyEventPrinter creates a new PolicyEventPrinter
func NewPolicyEventPrinter(pConfigs []config.PrinterConfig, policies []policy.PolicyFile, containerMode config.ContainerMode) (*PolicyEventPrinter, error) {
	p := &PolicyEventPrinter{
		printerConfigs: pConfigs,
		policies:       policies,
		containerMode:  containerMode,
	}
	return p, p.Init()
}

// Init serves as the initializer method for every event Printer type
func (pp *PolicyEventPrinter) Init() error {
	printerMap := make(map[string][]chan trace.Event)
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

		key := getKey(pConfig.Kind)

		_, ok := printerMap[key]
		if !ok {
			printerMap[key] = make([]chan trace.Event, 0)
		}

		printerMap[key] = append(printerMap[key], eventChan)
	}

	eventsMap, err := pp.createEventMap(printerMap)
	if err != nil {
		return err
	}

	pp.eventsMap = eventsMap
	pp.printerMap = printerMap
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
	executed := make(map[string]bool, 0)

	var printersExecuted int
	for _, policyName := range event.MatchedPolicies {
		if printersExecuted == pp.numOfPrinters {
			return
		}

		key := policyName + ":" + event.EventName

		action, ok := pp.eventsMap[key]
		if !ok {
			logger.Debugw("printers not found for event", "event", event)
			continue
		}

		// avoid executing the same printer twice
		if _, ok := executed[action]; ok {
			continue
		}

		eventChans, ok := pp.printerMap[action]
		if !ok {
			panic(fmt.Sprintf("printer not found %q", action))
		}

		for _, c := range eventChans {
			c <- event
		}

		printersExecuted++
		executed[action] = true
	}
}

// dispose of resources
func (pp *PolicyEventPrinter) Close() {
	for _, printer := range pp.printers {
		printer.Close()
	}
}

func (pp *PolicyEventPrinter) createEventMap(printerMap map[string][]chan trace.Event) (map[string]string, error) {
	eventsMap := make(map[string]string)

	for _, p := range pp.policies {
		for _, rule := range p.Rules {
			key := p.Name + ":" + rule.Event
			eventsMap[key] = p.DefaultAction

			if _, ok := printerMap[p.DefaultAction]; p.DefaultAction != "log" && !ok {
				return nil, errfmt.Errorf("policy action %q has no printer configured, please configure the printer with --output", p.DefaultAction)
			}

			// if no specific action is defined for this event, move on
			for _, action := range rule.Action {
				if action == "" {
					continue
				}

				eventsMap[key] = action

				if _, ok := printerMap[action]; action != "log" && !ok {
					return nil, errfmt.Errorf("policy action %q has no printer configured, please configure the printer with --output", rule.Action)
				}
			}
		}
	}

	return eventsMap, nil
}

func getKey(kind string) string {
	switch kind {
	case "forward":
		return "forward"
	case "webhook":
		return "webhook"
	default:
		return "log"
	}
}
