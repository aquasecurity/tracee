package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/tracee"
	"github.com/syndtr/gocapability/capability"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "Tracee",
		Usage: "Trace OS events and syscalls using eBPF",
		Action: func(c *cli.Context) error {
			if c.Bool("list") {
				printList()
				return nil
			}
			if c.IsSet("event") && c.IsSet("exclude-event") {
				return fmt.Errorf("'event' and 'exclude-event' can't be used in parallel")
			}
			events, err := prepareEventsToTrace(c.StringSlice("event"), c.StringSlice("events-set"), c.StringSlice("exclude-event"))
			if err != nil {
				return err
			}
			mode, pidsToTrace, err := prepareTraceMode(c.String("trace"))
			if err != nil {
				return err
			}

			cfg := tracee.TraceeConfig{
				EventsToTrace:         events,
				Mode:                  mode,
				DetectOriginalSyscall: c.Bool("detect-original-syscall"),
				ShowExecEnv:           c.Bool("show-exec-env"),
				OutputFormat:          c.String("output"),
				PerfBufferSize:        c.Int("perf-buffer-size"),
				PidsToTrace:           pidsToTrace,
				BlobPerfBufferSize:    c.Int("blob-perf-buffer-size"),
				OutputPath:            c.String("output-path"),
				FilterFileWrite:       c.StringSlice("filter-file-write"),
				SecurityAlerts:        c.Bool("security-alerts"),
				EventsFile:            os.Stdout,
				ErrorsFile:            os.Stderr,
			}
			capture := c.StringSlice("capture")
			for _, cap := range capture {
				if cap == "write" {
					cfg.CaptureWrite = true
				} else if cap == "exec" {
					cfg.CaptureExec = true
				} else if cap == "mem" {
					cfg.CaptureMem = true
				} else if cap == "all" {
					cfg.CaptureWrite = true
					cfg.CaptureExec = true
					cfg.CaptureMem = true
				} else {
					return fmt.Errorf("invalid capture option: %s", cap)
				}
			}
			if c.Bool("security-alerts") {
				cfg.EventsToTrace = append(cfg.EventsToTrace, tracee.MemProtAlertEventID)
			}
			if c.Bool("clear-output-path") {
				os.RemoveAll(cfg.OutputPath)
			}
			t, err := tracee.New(cfg)
			if err != nil {
				// t is being closed internally
				return fmt.Errorf("error creating Tracee: %v", err)
			}
			return t.Run()
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Value:   "table",
				Usage:   "output format: table/table-verbose/json/gob",
			},
			&cli.StringSliceFlag{
				Name:    "event",
				Aliases: []string{"e"},
				Value:   nil,
				Usage:   "trace only the specified event or syscall. use this flag multiple times to choose multiple events",
			},
			&cli.StringSliceFlag{
				Name:    "events-set",
				Aliases: []string{"s"},
				Value:   nil,
				Usage:   "trace all the events which belong to this set. use this flag multiple times to choose multiple sets",
			},
			&cli.StringSliceFlag{
				Name:  "exclude-event",
				Value: nil,
				Usage: "exclude an event from being traced. use this flag multiple times to choose multiple events to exclude",
			},
			&cli.BoolFlag{
				Name:    "list",
				Aliases: []string{"l"},
				Value:   false,
				Usage:   "just list tracable events",
			},
			&cli.StringFlag{
				Name:    "trace",
				Aliases: []string{"t"},
				Value:   "process:new",
				Usage:   "Set trace mode, whether to trace processes or containers, and if to trace new, all, or specific processes/container. run '--trace help' for more info",
			},
			&cli.BoolFlag{
				Name:  "detect-original-syscall",
				Value: false,
				Usage: "when tracing kernel functions which are not syscalls (such as cap_capable), detect and show the original syscall that called that function",
			},
			&cli.BoolFlag{
				Name:  "show-exec-env",
				Value: false,
				Usage: "when tracing execve/execveat, show environment variables",
			},
			&cli.IntFlag{
				Name:    "perf-buffer-size",
				Aliases: []string{"b"},
				Value:   1024,
				Usage:   "size, in pages, of the internal perf ring buffer used to submit events from the kernel",
			},
			&cli.IntFlag{
				Name:  "blob-perf-buffer-size",
				Value: 1024,
				Usage: "size, in pages, of the internal perf ring buffer used to send blobs from the kernel",
			},
			&cli.StringFlag{
				Name:  "output-path",
				Value: "/tmp/tracee",
				Usage: "set output path",
			},
			&cli.BoolFlag{
				Name:    "clear-output-path",
				Aliases: []string{"clear"},
				Value:   false,
				Usage:   "clear the output path before starting",
			},
			&cli.StringSliceFlag{
				Name:  "capture",
				Value: nil,
				Usage: "capture artifacts that were written, executed or found to be suspicious. captured artifacts will appear in the 'output-path' directory. possible values: 'write'/'exec'/'mem'/'all'. use this flag multiple times to choose multiple capture options",
			},
			&cli.StringSliceFlag{
				Name:  "filter-file-write",
				Value: nil,
				Usage: "only output file writes whose path starts with the given path prefix (up to 64 characters)",
			},
			&cli.BoolFlag{
				Name:  "security-alerts",
				Value: false,
				Usage: "alert on security related events",
			},
		},
	}

	if !isCapable() {
		log.Fatal("Not enough privileges to run this program")
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func prepareTraceMode(traceString string) (uint32, []int, error) {
	// Set Default mode - all new Processes only
	mode := tracee.ModeProcessNew
	var pidsToTrace []int
	traceHelp := "--trace can be the following options:\n"
	traceHelp += "'p' or 'process' or 'process:new'            | Trace new processes\n"
	traceHelp += "'process:all'                                | Trace all processes\n"
	traceHelp += "'process:<pid>,<pid2>,...' or 'p:<pid>,...'  | Trace specific PIDs\n"
	traceHelp += "'c' or 'container' or 'container:new'        | Trace new containers\n"
	traceHelp += "'container:all'                              | Trace all containers\n"
	if traceString == "help" {
		return 0, nil, fmt.Errorf(traceHelp)
	}

	traceSplit := strings.Split(traceString, ":")

	// Get The trace type - process or  container
	traceType := traceSplit[0]
	if traceType != "process" && traceType != "container" && traceType != "p" && traceType != "c" {
		return 0, nil, fmt.Errorf(traceHelp)
	}
	traceType = string(traceType[0])

	// Get The trace option, default is 'new' for all trace types:
	traceOption := "new"
	if len(traceSplit) == 2 {
		traceOption = traceSplit[1]
	} else if len(traceSplit) > 2 {
		return 0, nil, fmt.Errorf(traceHelp)
	}

	// Convert to Traceing Mode
	if traceType == "p" {
		if traceOption == "all" {
			mode = tracee.ModeProcessAll
		} else if traceOption == "new" {
			mode = tracee.ModeProcessNew
		} else if len(traceOption) != 0 {
			mode = tracee.ModeProcessList
			// Attempt to split into PIDs
			for _, pidString := range strings.Split(traceOption, ",") {
				pid, err := strconv.ParseInt(pidString, 10, 32)
				if err != nil {
					return 0, nil, fmt.Errorf(traceHelp)
				}
				pidsToTrace = append(pidsToTrace, int(pid))
			}
		} else {
			// Can't have just 'process:'
			return 0, nil, fmt.Errorf(traceHelp)
		}
	} else {
		if traceOption == "all" {
			mode = tracee.ModeContainerAll
		} else if traceOption == "new" {
			mode = tracee.ModeContainerNew
		} else {
			// Containers currently only supports 'new' and 'all'
			return 0, nil, fmt.Errorf(traceHelp)
		}
	}
	return mode, pidsToTrace, nil
}

func prepareEventsToTrace(eventsToTrace []string, setsToTrace []string, excludeEvents []string) ([]int32, error) {
	var res []int32
	eventsNameToID := make(map[string]int32, len(tracee.EventsIDToEvent))
	setsToEvents := make(map[string][]int32)
	isExcluded := make(map[int32]bool)
	for id, event := range tracee.EventsIDToEvent {
		eventsNameToID[event.Name] = event.ID
		for _, set := range event.Sets {
			setsToEvents[set] = append(setsToEvents[set], id)
		}
	}
	for _, name := range excludeEvents {
		id, ok := eventsNameToID[name]
		if !ok {
			return nil, fmt.Errorf("invalid event to exclude: %s", name)
		}
		isExcluded[id] = true
	}
	if eventsToTrace == nil && setsToTrace == nil {
		setsToTrace = append(setsToTrace, "default")
	}

	res = make([]int32, 0, len(tracee.EventsIDToEvent))
	for _, name := range eventsToTrace {
		id, ok := eventsNameToID[name]
		if !ok {
			return nil, fmt.Errorf("invalid event to trace: %s", name)
		}
		res = append(res, id)
	}
	for _, set := range setsToTrace {
		setEvents, ok := setsToEvents[set]
		if !ok {
			return nil, fmt.Errorf("invalid set to trace: %s", set)
		}
		for _, id := range setEvents {
			if !isExcluded[id] {
				res = append(res, id)
			}
		}
	}
	return res, nil
}

func isCapable() bool {
	c, err := capability.NewPid2(0)
	if err != nil {
		fmt.Println("Current user capabilities could not be retrieved. Assure running with enough privileges")
		return true
	}
	err = c.Load()
	if err != nil {
		fmt.Println("Current user capabilities could not be retrieved. Assure running with enough privileges")
		return true
	}

	return c.Get(capability.EFFECTIVE, capability.CAP_SYS_ADMIN)
}

func printList() {
	var b strings.Builder
	b.WriteString("System Calls:              Sets:\n")
	b.WriteString("____________               ____\n\n")
	for i := 0; i < int(tracee.SysEnterEventID); i++ {
		event := tracee.EventsIDToEvent[int32(i)]
		if event.Name == "reserved" {
			continue
		}
		if event.Sets != nil {
			eventSets := fmt.Sprintf("%-23s    %v\n", event.Name, event.Sets)
			b.WriteString(eventSets)
		} else {
			b.WriteString(event.Name + "\n")
		}
	}
	b.WriteString("\n\nOther Events:              Sets:\n")
	b.WriteString("____________               ____\n\n")
	for i := int(tracee.SysEnterEventID); i < len(tracee.EventsIDToEvent); i++ {
		event := tracee.EventsIDToEvent[int32(i)]
		if event.Sets != nil {
			eventSets := fmt.Sprintf("%-23s    %v\n", event.Name, event.Sets)
			b.WriteString(eventSets)
		} else {
			b.WriteString(event.Name + "\n")
		}
	}
	fmt.Println(b.String())
}
