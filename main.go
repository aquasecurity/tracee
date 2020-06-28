package main

import (
	"fmt"
	"log"
	"os"
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
			events, err := prepareEventsToTrace(c.StringSlice("event"))
			if err != nil {
				return err
			}
			cfg := tracee.TraceeConfig{
				EventsToTrace:         events,
				ContainerMode:         c.Bool("container"),
				DetectOriginalSyscall: c.Bool("detect-original-syscall"),
				ShowExecEnv:           c.Bool("show-exec-env"),
				OutputFormat:          c.String("output"),
				PerfBufferSize:        c.Int("perf-buffer-size"),
				OutputPath:            c.String("output-path"),
				CaptureFiles:          c.Bool("capture-files"),
				FilterFileWrite:       c.StringSlice("filter-file-write"),
				EventsFile:            os.Stdout,
			}
			if c.Bool("show-all-syscalls") {
				cfg.EventsToTrace = append(cfg.EventsToTrace, tracee.EventsNameToID["raw_syscalls"])
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
				Usage:   "output format: table (default)/json",
			},
			&cli.StringSliceFlag{
				Name:    "event",
				Aliases: []string{"e"},
				Value:   nil,
				Usage:   "trace only the specified event or syscall. use this flag multiple times to choose multiple events",
			},
			&cli.BoolFlag{
				Name:    "list",
				Aliases: []string{"l"},
				Value:   false,
				Usage:   "just list tracable events",
			},
			&cli.BoolFlag{
				Name:    "container",
				Aliases: []string{"c"},
				Value:   false,
				Usage:   "trace only containers",
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
				Value:   64,
				Usage:   "size, in pages, of the internal perf ring buffer used to submit events from the kernel",
			},
			&cli.BoolFlag{
				Name:    "show-all-syscalls",
				Aliases: []string{"a"},
				Value:   false,
				Usage:   "log all syscalls invocations, including syscalls which were not fully traced by tracee (shortcut to -e raw_syscalls)",
			},
			&cli.StringFlag{
				Name:  "output-path",
				Value: "/tmp/tracee",
				Usage: "set output path",
			},
			&cli.BoolFlag{
				Name:  "capture-files",
				Value: false,
				Usage: "capture file writes to output path",
			},
			&cli.StringSliceFlag{
				Name:  "filter-file-write",
				Value: nil,
				Usage: "only output file writes whose path starts with the given path prefix (up to 64 characters)",
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

func prepareEventsToTrace(eventsToTrace []string) ([]int32, error) {
	var res []int32
	if eventsToTrace == nil {
		res = make([]int32, 0, len(tracee.EventsIDToName))
		rawSyscallsID := tracee.EventsNameToID["raw_syscalls"]
		for id := range tracee.EventsIDToName {
			if id != rawSyscallsID {
				res = append(res, id)
			}
		}
	} else {
		res = make([]int32, 0, len(eventsToTrace))
		for _, name := range eventsToTrace {
			id, ok := tracee.EventsNameToID[name]
			if !ok {
				return nil, fmt.Errorf("invalid event to trace: %s", name)
			}
			res = append(res, id)
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
	const sep = ", "
	var b strings.Builder
	for _, name := range tracee.EventsSyscalls {
		b.WriteString(name)
		b.WriteString(sep)
	}
	fmt.Println("System calls:")
	fmt.Println(strings.TrimSuffix(b.String(), sep))
	b.Reset()
	fmt.Println()

	for _, name := range tracee.EventsTracepoints {
		b.WriteString(name)
		b.WriteString(sep)
	}
	fmt.Println("Tracepoints:")
	fmt.Println(strings.TrimSuffix(b.String(), sep))
	b.Reset()
	fmt.Println()

	for _, name := range tracee.EventsKprobes {
		b.WriteString(name)
		b.WriteString(sep)
	}
	fmt.Println("System events:")
	fmt.Println(strings.TrimSuffix(b.String(), sep))
}
