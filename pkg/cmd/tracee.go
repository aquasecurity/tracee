package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/server"
)

type Runner struct {
	TraceeConfig  tracee.Config
	PrinterConfig printer.Config
	Server        *server.Server
}

func (r Runner) Run(ctx context.Context) error {
	// Create Tracee Singleton

	t, err := tracee.New(r.TraceeConfig)
	if err != nil {
		return fmt.Errorf("error creating Tracee: %v", err)
	}

	// Decide if HTTP server should be started

	if r.Server != nil {
		if r.Server.MetricsEndpointEnabled() {
			err := t.Stats().RegisterPrometheus()
			if err != nil {
				logger.Error("registering prometheus metrics", "error", err)
			}
		}

		go r.Server.Start()
	}

	// Configure the events printer

	printer, err := printer.New(r.PrinterConfig)
	if err != nil {
		return err
	}

	// Print statistics at the end

	defer func() {
		stats := t.Stats()
		printer.Epilogue(*stats)
		printer.Close()
	}()

	// Initialize tracee

	err = t.Init()
	if err != nil {
		return fmt.Errorf("error initializing Tracee: %v", err)
	}

	// Print the preamble and start event channel reception

	go func() {
		printer.Preamble()
		for {
			select {
			case event := <-r.TraceeConfig.ChanEvents:
				printer.Print(event)
			case <-ctx.Done():
				return
			}
		}
	}()

	return t.Run(ctx) // return when context is cancelled by signal
}

func PrintEventList(printRulesSet bool) {
	padChar := " "
	titleHeaderPadFirst := getPad(padChar, 24)
	titleHeaderPadSecond := getPad(padChar, 36)

	var b strings.Builder

	if printRulesSet {
		b.WriteString("Rules: " + titleHeaderPadFirst + "Sets:" + titleHeaderPadSecond + "Arguments:\n")
		b.WriteString("_____  " + titleHeaderPadFirst + "____ " + titleHeaderPadSecond + "_________" + "\n\n")
		printEventGroup(&b, events.StartSignatureID, events.MaxSignatureID)
		b.WriteString("\n")
	}

	titleHeaderPadFirst = getPad(padChar, 17)
	b.WriteString("System Calls: " + titleHeaderPadFirst + "Sets:" + titleHeaderPadSecond + "Arguments:\n")
	b.WriteString("____________  " + titleHeaderPadFirst + "____ " + titleHeaderPadSecond + "_________" + "\n\n")
	printEventGroup(&b, 0, events.MaxSyscallID)
	b.WriteString("\n\nOther Events: " + titleHeaderPadFirst + "Sets:" + titleHeaderPadSecond + "Arguments:\n")
	b.WriteString("____________  " + titleHeaderPadFirst + "____ " + titleHeaderPadSecond + "_________\n\n")
	printEventGroup(&b, events.SysEnter, events.MaxCommonID)
	printEventGroup(&b, events.InitNamespaces, events.MaxUserSpace)

	titleHeaderPadFirst = getPad(padChar, 15)
	b.WriteString("\n\nNetwork Events: " + titleHeaderPadFirst + "Sets:" + titleHeaderPadSecond + "Arguments:\n")
	b.WriteString("______________  " + titleHeaderPadFirst + "____ " + titleHeaderPadSecond + "_________\n\n")
	printEventGroup(&b, events.NetPacketIPv4, events.MaxUserNetID)
	fmt.Println(b.String())
}

func printEventGroup(b *strings.Builder, firstEventID, lastEventID events.ID) {
	for i := firstEventID; i < lastEventID; i++ {
		event, ok := events.Definitions.GetSafe(i)
		if !ok || event.Internal {
			continue
		}
		if event.Sets != nil {
			eventSets := fmt.Sprintf("%-30s %-40s %s\n", event.Name, fmt.Sprintf("%v", event.Sets), getFormattedEventParams(i))
			b.WriteString(eventSets)
		} else {
			b.WriteString(event.Name + "\n")
		}
	}
}

func getFormattedEventParams(eventID events.ID) string {
	evtDef, exists := events.Definitions.GetSafe(eventID)
	if !exists {
		return "()"
	}
	eventParams := evtDef.Params
	var verboseEventParams string
	verboseEventParams += "("
	prefix := ""
	for index, arg := range eventParams {
		if index == 0 {
			verboseEventParams += arg.Type + " " + arg.Name
			prefix = ", "
			continue
		}
		verboseEventParams += prefix + arg.Type + " " + arg.Name
	}
	verboseEventParams += ")"
	return verboseEventParams
}

func getPad(padChar string, padLength int) (pad string) {
	for i := 0; i < padLength; i++ {
		pad += padChar
	}
	return
}

func GetContainerMode(cfg tracee.Config) printer.ContainerMode {
	containerMode := printer.ContainerModeDisabled

	for filterScope := range cfg.FilterScopes.Map() {
		if filterScope.ContainerFilterEnabled() {
			// enable printer container print mode if container filters are set
			containerMode = printer.ContainerModeEnabled
			if cfg.ContainersEnrich {
				// further enable container enrich print mode if container enrichment is enabled
				containerMode = printer.ContainerModeEnriched
			}

			break
		}
	}

	return containerMode
}
