package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/pkg/config"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/server"
	"github.com/aquasecurity/tracee/pkg/utils"
)

type Runner struct {
	TraceeConfig config.Config
	Printer      printer.EventPrinter
	Server       *server.Server
}

func (r Runner) Run(ctx context.Context) error {
	// Create Tracee Singleton

	t, err := tracee.New(r.TraceeConfig)
	if err != nil {
		return errfmt.Errorf("error creating Tracee: %v", err)
	}

	// Readiness Callback: Tracee is ready to receive events

	t.AddReadyCallback(
		func(ctx context.Context) {
			logger.Debugw("Tracee is ready callback")
			if r.Server == nil {
				return
			}
			if r.Server.MetricsEndpointEnabled() {
				r.TraceeConfig.MetricsEnabled = true // TODO: is this needed ?
				if err := t.Stats().RegisterPrometheus(); err != nil {
					logger.Errorw("Registering prometheus metrics", "error", err)
				}
			}
			go r.Server.Start(ctx)
		},
	)

	// Initialize tracee

	err = t.Init()
	if err != nil {
		return errfmt.Errorf("error initializing Tracee: %v", err)
	}

	// Manage PID file

	if err := writePidFile(t.OutDir); err != nil {
		return errfmt.WrapError(err)
	}
	defer func() {
		if err := removePidFile(t.OutDir); err != nil {
			logger.Warnw("error removing pid file", "error", err)
		}
	}()

	// Preeamble

	r.Printer.Preamble()

	// Start event channel reception

	go func() {
		for {
			select {
			case event := <-r.TraceeConfig.ChanEvents:
				r.Printer.Print(event)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Blocks (until ctx is Done)

	err = t.Run(ctx)

	// Drain remaininig channel events (sent during shutdown)

	for {
		select {
		case event := <-r.TraceeConfig.ChanEvents:
			r.Printer.Print(event)
		default:
			stats := t.Stats()
			r.Printer.Epilogue(*stats)
			r.Printer.Close()
			return err
		}
	}
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
		if !events.Core.IsDefined(i) {
			continue
		}
		eventDefinition := events.Core.GetDefinitionByID(i)
		if eventDefinition.IsInternal() {
			continue
		}
		if eventDefinition.GetSets() != nil {
			eventSets := fmt.Sprintf(
				"%-30s %-40s %s\n",
				eventDefinition.GetName(),
				fmt.Sprintf("%v", eventDefinition.GetSets()), getFormattedEventParams(i),
			)
			b.WriteString(eventSets)
		} else {
			b.WriteString(eventDefinition.GetName() + "\n")
		}
	}
}

func getFormattedEventParams(eventID events.ID) string {
	if !events.Core.IsDefined(eventID) {
		return "()"
	}
	var verboseEventParams string
	verboseEventParams += "("
	prefix := ""
	for index, arg := range events.Core.GetDefinitionByID(eventID).GetParams() {
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
	return pad
}

func GetContainerMode(cfg config.Config) config.ContainerMode {
	containerMode := config.ContainerModeDisabled

	for p := range cfg.Policies.Map() {
		if p.ContainerFilterEnabled() {
			// enable printer container print mode if container filters are set
			containerMode = config.ContainerModeEnabled
			if cfg.ContainersEnrich {
				// further enable container enrich print mode if container enrichment is enabled
				containerMode = config.ContainerModeEnriched
			}

			break
		}
	}

	return containerMode
}

const pidFileName = "tracee.pid"

// Initialize PID file
func writePidFile(dir *os.File) error {
	pidFile, err := utils.OpenAt(dir, pidFileName, syscall.O_WRONLY|syscall.O_CREAT, 0640)
	if err != nil {
		return errfmt.Errorf("error creating readiness file: %v", err)
	}

	_, err = pidFile.Write([]byte(strconv.Itoa(os.Getpid()) + "\n"))
	if err != nil {
		return errfmt.Errorf("error writing to readiness file: %v", err)
	}

	return nil
}

// Remove PID file
func removePidFile(dir *os.File) error {
	if err := utils.RemoveAt(dir, pidFileName, 0); err != nil {
		return errfmt.Errorf("%v", err)
	}

	return nil
}
