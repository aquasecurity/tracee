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
	printerMap     map[string]chan trace.Event
	policyMap      map[string]string
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

	// key -> policy:event, or policy
	// val -> printerName
	// eg:
	// 	"policy1:open" -> "webhook:https://webhook.site/..."
	// 	"policy1" -> "json:stdout"
	policyMap := make(map[string]string)

	for _, p := range pp.policies {
		for _, rule := range p.Rules {
			if rule.Action == "" {
				continue
			}

			// action for this specif event at this policy
			key := p.Name + ":" + rule.Event
			policyMap[key] = getAction(rule.Action)
		}

		// default action for this policy
		policyMap[p.Name] = getAction(p.DefaultAction)
	}

	pp.printerMap = printerMap
	pp.policyMap = policyMap
	pp.wg = wg
	pp.printers = printers
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
	for _, policyName := range event.MatchedPoliciesNames {
		// if the event overrides the default action
		key := policyName + ":" + event.EventName
		if printerName, ok := pp.policyMap[key]; ok {
			c, ok := pp.printerMap[printerName]
			if !ok {
				logger.Fatalw("printer not found", "printerName", printerName)
			}
			c <- event
			continue
		}

		// policy default action
		key = policyName
		if printerName, ok := pp.policyMap[key]; ok {
			c, ok := pp.printerMap[printerName]
			if !ok {
				logger.Fatalw("printer not found", "printerName", printerName)
			}
			c <- event
			continue
		}
	}
}

// dispose of resources
func (pp *PolicyEventPrinter) Close() {
	for _, printer := range pp.printers {
		printer.Close()
	}
}

func getKey(policyName, eventName string) string {
	return policyName + ":" + eventName
}

func getAction(action string) string {
	if action == "log" {
		return "json:stdout"
	}
	return action
}
