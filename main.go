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

			// Set Default mode
			mode := tracee.ModeProcessNew
			var pidsToTrace []int
			if c.IsSet("container") && c.IsSet("pid") {
				return fmt.Errorf("'container' and 'pid' can't be used in parallel")
			} else if c.IsSet("container") {
				// Right now we only support 'new', 'all', or not set, but future we may want to
				// support specific container IDs
				if c.String("container") == "all" {
					mode = tracee.ModeContainerAll
				} else if c.String("container") == "new" {
					mode = tracee.ModeContainerNew
				} else {
					return fmt.Errorf("Invalid container: %s", c.String("container"))
				}
			} else if c.IsSet("pid") {
				hasExclusiveOption := false
				hasIDOption := false
				for _, pidFilter := range c.StringSlice("pid") {
					if hasExclusiveOption {
						return fmt.Errorf("pid 'all', 'new', and '<process_id>' are all mutually exclusive")
					}
					if pidFilter == "new" || pidFilter == "all" {
						hasExclusiveOption = true
						if hasIDOption {
							return fmt.Errorf("pid 'all', 'new', and '<process_id>' are all mutually exclusive")
						}
						if pidFilter == "all" {
							mode = tracee.ModeProcessAll
						} else {
							mode = tracee.ModeProcessNew
						}
					} else {
						hasIDOption = true
						mode = tracee.ModeProcessList
						pid, err := strconv.ParseInt(pidFilter, 10, 32)
						if err != nil {
							return fmt.Errorf("Invalid pid option: %s", pidFilter)
						}
						pidsToTrace = append(pidsToTrace, int(pid))
					}
				}
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
				Name:    "container",
				Aliases: []string{"c"},
				Value:   "new",
				Usage:   "container filtering setting. Options are 'new' to trace only new containers; 'all' to trace all presesses inside containers.",
			},
			&cli.StringSliceFlag{
				Name:    "pid",
				Aliases: []string{"p"},
				Value:   nil,
				Usage:   "pid filtering setting. Options are: 'new' to trace only new pids (default); 'all' to trace all pids; '<process_id>' to trace only the specified process id, e.g. '-p 123'. Use '<process_id>' flag multiple times to choose multiple pids",
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
