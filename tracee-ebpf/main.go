package main

import (
	"embed"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/libbpfgo/helpers"
	"github.com/aquasecurity/tracee/tracee-ebpf/tracee"
	"github.com/syndtr/gocapability/capability"
	cli "github.com/urfave/cli/v2"
)

var debug bool
var traceeInstallPath string
var buildPolicy string

// These vars are supposed to be injected at build time
//go:embed "dist/tracee.bpf/*"
var bpfBundleInjected embed.FS
var version string

func main() {
	app := &cli.App{
		Name:    "Tracee",
		Usage:   "Trace OS events and syscalls using eBPF",
		Version: version,
		Action: func(c *cli.Context) error {
			if c.Bool("list") {
				printList()
				return nil
			}

			cfg := tracee.Config{
				PerfBufferSize:     c.Int("perf-buffer-size"),
				BlobPerfBufferSize: c.Int("blob-perf-buffer-size"),
				SecurityAlerts:     c.Bool("security-alerts"),
			}
			output, err := prepareOutput(c.StringSlice("output"))
			if err != nil {
				return err
			}
			cfg.Output = &output
			capture, err := prepareCapture(c.StringSlice("capture"))
			if err != nil {
				return err
			}
			cfg.Capture = &capture
			filter, err := prepareFilter(c.StringSlice("trace"))
			if err != nil {
				return err
			}
			cfg.Filter = &filter

			if c.Bool("security-alerts") {
				cfg.Filter.EventsToTrace = append(cfg.Filter.EventsToTrace, tracee.MemProtAlertEventID)
			}
			bpfFile, err := getBPFObject()
			if err != nil {
				return err
			}
			cfg.BPFObjPath = bpfFile
			if !checkRequiredCapabilities() {
				return fmt.Errorf("insufficient privileges to run")
			}
			missingKernelOptions := missingKernelConfigOptions()
			if len(missingKernelOptions) != 0 {
				return fmt.Errorf("kernel is not properly configured, missing: %v", missingKernelOptions)
			}
			t, err := tracee.New(cfg)
			if err != nil {
				return fmt.Errorf("error creating Tracee: %v", err)
			}
			return t.Run()
		},
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "list",
				Aliases: []string{"l"},
				Value:   false,
				Usage:   "just list tracable events",
			},
			&cli.StringSliceFlag{
				Name:    "trace",
				Aliases: []string{"t"},
				Value:   nil,
				Usage:   "select events to trace by defining trace expressions. run '--trace help' for more info.",
			},
			&cli.StringSliceFlag{
				Name:    "capture",
				Aliases: []string{"c"},
				Value:   nil,
				Usage:   "capture artifacts that were written, executed or found to be suspicious. run '--capture help' for more info.",
			},
			&cli.StringSliceFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Value:   cli.NewStringSlice("format:table"),
				Usage:   "Control how and where output is printed. run '--output help' for more info.",
			},
			&cli.BoolFlag{
				Name:  "security-alerts",
				Value: false,
				Usage: "alert on security related events",
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
			&cli.BoolFlag{
				Name:        "debug",
				Value:       false,
				Usage:       "write verbose debug messages to standard output and retain intermediate artifacts",
				Destination: &debug,
			},
			&cli.StringFlag{
				Name:        "install-path",
				Value:       "/tmp/tracee",
				Usage:       "path where tracee will install or lookup it's resources",
				Destination: &traceeInstallPath,
			},
			&cli.StringFlag{
				Name:        "build-policy",
				Value:       "if-needed",
				Usage:       "when to build the bpf program. possible options: 'never'/'always'/'if-needed'",
				Destination: &buildPolicy,
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func prepareOutput(outputSlice []string) (tracee.OutputConfig, error) {
	outputHelp := `
Control how and where output is printed.
Possible options:

[format:]{table,table-verbose,json,gob,gotemplate=/path/to/template}   output events in the specified format. for gotemplate, specify the mandatory template file
out-file:/path/to/file                                                 write the output to a specified file. the path to the file will be created if not existing and the file will be deleted if existing (default: stdout)
err-file:/path/to/file                                                 write the errors to a specified file. the path to the file will be created if not existing and the file will be deleted if existing (default: stderr)
option:{stack-addresses,detect-syscall,exec-env}                       augment output according to given options (default: none)
  stack-addresses                                                    include stack memory addresses for each event
  detect-syscall                                                     when tracing kernel functions which are not syscalls, detect and show the original syscall that called that function
  exec-env                                                           when tracing execve/execveat, show the environment variables that were used for execution
Examples:
  --output json                                            | output as json
  --output gotemplate=/path/to/my.tmpl                     | output as the provided go template
  --output out-file:/my/out err-file:/my/err               | output to /my/out and errors to /my/err

Use this flag multiple times to choose multiple capture options	
`

	res := tracee.OutputConfig{}
	if len(outputSlice) == 1 && outputSlice[0] == "help" {
		return res, fmt.Errorf(outputHelp)
	}

	for _, o := range outputSlice {
		outputParts := strings.SplitN(o, ":", 2)
		numParts := len(outputParts)
		if numParts == 1 {
			res.Format = outputParts[0]
			err := res.Validate()
			if err != nil {
				return res, err
			}
			outputParts = append(outputParts, outputParts[0])
			outputParts[0] = "format"
		}

		switch outputParts[0] {
		case "format":
			res.Format = outputParts[1]
			err := res.Validate()
			if err != nil {
				return res, err
			}
		case "out-file":
			res.OutPath = outputParts[1]
		case "err-file":
			res.ErrPath = outputParts[1]
		case "option":
			switch outputParts[1] {
			case "stack-addresses":
				res.StackAddresses = true
			case "detect-syscall":
				res.DetectSyscall = true
			case "exec-env":
				res.ExecEnv = true
			default:
				return res, fmt.Errorf("invalid output option: %s, use '--output help' for more info", outputParts[1])
			}
		default:
			return res, fmt.Errorf("invalid output value: %s, use '--output help' for more info", outputParts[1])
		}
	}

	if res.Format == "" {
		res.Format = "table"
	}
	return res, nil
}

func prepareCapture(captureSlice []string) (tracee.CaptureConfig, error) {
	captureHelp := `
Capture artifacts that were written, executed or found to be suspicious.
Captured artifacts will appear in the 'output-path' directory.
Possible options:

[artifact:]write[=/path/prefix*]   capture written files. A filter can be given to only capture file writes whose path starts with some prefix (up to 50 characters). Up to 3 filters can be given.
[artifact:]exec                    capture executed files.
[artifact:]mem                     capture memory regions that had write+execute (w+x) protection, and then changed to execute (x) only.
[artifact:]all                     capture all of the above artifacts.

dir:/path/to/dir        path where tracee will save produced artifacts. the artifact will be saved into an 'out' subdirectory. (default: /tmp/tracee).
clear-dir               clear the captured artifacts output dir before starting (default: false).

Examples:
  --capture exec                                           | capture executed files into the default output directory
  --capture all --capture dir:/my/dir --capture clear-dir  | delete /my/dir/out and then capture all supported artifacts into it
  --capture write=/usr/bin/* --capture write=/etc/*        | capture files that were written into anywhere under /usr/bin/ or /etc/

Use this flag multiple times to choose multiple capture options
`

	if len(captureSlice) == 1 && captureSlice[0] == "help" {
		return tracee.CaptureConfig{}, fmt.Errorf(captureHelp)
	}

	capture := tracee.CaptureConfig{}

	outDir := "/tmp/tracee"
	clearDir := false

	var filterFileWrite []string
	for i := range captureSlice {
		cap := captureSlice[i]
		if strings.HasPrefix(cap, "artifact:write") ||
			strings.HasPrefix(cap, "artifact:exec") ||
			strings.HasPrefix(cap, "artifact:mem") ||
			strings.HasPrefix(cap, "artifact:all") {
			cap = strings.TrimPrefix(cap, "artifact:")
		}
		if cap == "write" {
			capture.FileWrite = true
		} else if strings.HasPrefix(cap, "write=") && strings.HasSuffix(cap, "*") {
			capture.FileWrite = true
			pathPrefix := strings.TrimSuffix(strings.TrimPrefix(cap, "write="), "*")
			if len(pathPrefix) == 0 {
				return tracee.CaptureConfig{}, fmt.Errorf("capture write filter cannot be empty")
			}
			filterFileWrite = append(filterFileWrite, pathPrefix)
		} else if cap == "exec" {
			capture.Exec = true
		} else if cap == "mem" {
			capture.Mem = true
		} else if cap == "all" {
			capture.FileWrite = true
			capture.Exec = true
			capture.Mem = true
		} else if cap == "clear-dir" {
			clearDir = true
		} else if strings.HasPrefix(cap, "dir:") {
			outDir = strings.TrimPrefix(cap, "dir:")
			if len(outDir) == 0 {
				return tracee.CaptureConfig{}, fmt.Errorf("capture output dir cannot be empty")
			}
		} else {
			return tracee.CaptureConfig{}, fmt.Errorf("invalid capture option specified, use '--capture help' for more info")
		}
	}
	capture.FilterFileWrite = filterFileWrite

	capture.OutputPath = filepath.Join(outDir, "out")
	if clearDir {
		os.RemoveAll(capture.OutputPath)
	}

	return capture, nil
}

func prepareFilter(filters []string) (tracee.Filter, error) {
	filterHelp := `
Select which events to trace by defining trace expressions that operate on events or process metadata.
Only events that match all trace expressions will be traced (trace flags are ANDed).
The following types of expressions are supported:

Numerical expressions which compare numbers and allow the following operators: '=', '!=', '<', '>'.
Available numerical expressions: uid, pid, mntns, pidns.

String expressions which compares text and allow the following operators: '=', '!='.
Available string expressions: event, set, uts, comm.

Boolean expressions that check if a boolean is true and allow the following operator: '!'.
Available boolean expressions: container.

Event arguments can be accessed using 'event_name.event_arg' and provide a way to filter an event by its arguments.
Event arguments allow the following operators: '=', '!='.
Strings can be compared as a prefix if ending with '*'.

Event return value can be accessed using 'event_name.retval' and provide a way to filter an event by its return value.
Event return value expression has the same syntax as a numerical expression.

Non-boolean expressions can compare a field to multiple values separated by ','.
Multiple values are ORed if used with equals operator '=', but are ANDed if used with any other operator.

The field 'container' and 'pid' also support the special value 'new' which selects new containers or pids, respectively.

The field 'set' selects a set of events to trace according to predefined sets, which can be listed by using the 'list' flag.

The special 'follow' expression declares that not only processes that match the criteria will be traced, but also their descendants.

Examples:
  --trace pid=new                                              | only trace events from new processes
  --trace pid=510,1709                                         | only trace events from pid 510 or pid 1709
  --trace p=510 --trace p=1709                                 | only trace events from pid 510 or pid 1709 (same as above)
  --trace container=new                                        | only trace events from newly created containers
  --trace container                                            | only trace events from containers
  --trace c                                                    | only trace events from containers (same as above)
  --trace '!container'                                         | only trace events from the host
  --trace uid=0                                                | only trace events from uid 0
  --trace mntns=4026531840                                     | only trace events from mntns id 4026531840
  --trace pidns!=4026531836                                    | only trace events from pidns id not equal to 4026531840
  --trace 'uid>0'                                              | only trace events from uids greater than 0
  --trace 'pid>0' --trace 'pid<1000'                           | only trace events from pids between 0 and 1000
  --trace 'u>0' --trace u!=1000                                | only trace events from uids greater than 0 but not 1000
  --trace event=execve,open                                    | only trace execve and open events
  --trace event=open*                                          | only trace events prefixed by "open"
  --trace event!=open*,dup*                                    | don't trace events prefixed by "open" or "dup"
  --trace set=fs                                               | trace all file-system related events
  --trace s=fs --trace e!=open,openat                          | trace all file-system related events, but not open(at)
  --trace uts!=ab356bc4dd554                                   | don't trace events from uts name ab356bc4dd554
  --trace comm=ls                                              | only trace events from ls command
  --trace close.fd=5                                           | only trace 'close' events that have 'fd' equals 5
  --trace openat.pathname=/tmp*                                | only trace 'openat' events that have 'pathname' prefixed by "/tmp"
  --trace openat.pathname!=/tmp/1,/bin/ls                      | don't trace 'openat' events that have 'pathname' equals /tmp/1 or /bin/ls
  --trace comm=bash --trace follow                             | trace all events that originated from bash or from one of the processes spawned by bash


Note: some of the above operators have special meanings in different shells.
To 'escape' those operators, please use single quotes, e.g.: 'uid>0'
`

	if len(filters) == 1 && filters[0] == "help" {
		return tracee.Filter{}, fmt.Errorf(filterHelp)
	}

	filter := tracee.Filter{
		UIDFilter: &tracee.UintFilter{
			Equal:    []uint64{},
			NotEqual: []uint64{},
			Less:     tracee.LessNotSetUint,
			Greater:  tracee.GreaterNotSetUint,
			Is32Bit:  true,
		},
		PIDFilter: &tracee.UintFilter{
			Equal:    []uint64{},
			NotEqual: []uint64{},
			Less:     tracee.LessNotSetUint,
			Greater:  tracee.GreaterNotSetUint,
			Is32Bit:  true,
		},
		NewPidFilter: &tracee.BoolFilter{},
		MntNSFilter: &tracee.UintFilter{
			Equal:    []uint64{},
			NotEqual: []uint64{},
			Less:     tracee.LessNotSetUint,
			Greater:  tracee.GreaterNotSetUint,
		},
		PidNSFilter: &tracee.UintFilter{
			Equal:    []uint64{},
			NotEqual: []uint64{},
			Less:     tracee.LessNotSetUint,
			Greater:  tracee.GreaterNotSetUint,
		},
		UTSFilter: &tracee.StringFilter{
			Equal:    []string{},
			NotEqual: []string{},
		},
		CommFilter: &tracee.StringFilter{
			Equal:    []string{},
			NotEqual: []string{},
		},
		ContFilter:    &tracee.BoolFilter{},
		NewContFilter: &tracee.BoolFilter{},
		RetFilter: &tracee.RetFilter{
			Filters: make(map[int32]tracee.IntFilter),
		},
		ArgFilter: &tracee.ArgFilter{
			Filters: make(map[int32]map[string]tracee.ArgFilterVal),
		},
		EventsToTrace: []int32{},
	}

	eventFilter := &tracee.StringFilter{Equal: []string{}, NotEqual: []string{}}
	setFilter := &tracee.StringFilter{Equal: []string{}, NotEqual: []string{}}

	eventsNameToID := make(map[string]int32, len(tracee.EventsIDToEvent))
	for _, event := range tracee.EventsIDToEvent {
		eventsNameToID[event.Name] = event.ID
	}

	for _, f := range filters {
		filterName := f
		operatorAndValues := ""
		operatorIndex := strings.IndexAny(f, "=!<>")
		if operatorIndex > 0 {
			filterName = f[0:operatorIndex]
			operatorAndValues = f[operatorIndex:]
		}

		if strings.Contains(f, ".retval") {
			err := parseRetFilter(filterName, operatorAndValues, eventsNameToID, filter.RetFilter)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if strings.Contains(f, ".") {
			err := parseArgFilter(filterName, operatorAndValues, eventsNameToID, filter.ArgFilter)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		// The filters which are more common (container, event, pid, set, uid) can be given using a prefix of them.
		// Other filters should be given using their full name.
		// To avoid collisions between filters that share the same prefix, put the filters which should have an exact match first!
		if filterName == "comm" {
			err := parseStringFilter(operatorAndValues, filter.CommFilter)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if strings.HasPrefix("container", f) || (strings.HasPrefix("!container", f) && len(f) > 1) {
			filter.NewPidFilter.Enabled = true
			filter.NewPidFilter.Value = true
			err := parseBoolFilter(f, filter.ContFilter)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if strings.HasPrefix("container", filterName) {
			if operatorAndValues == "=new" {
				filter.NewPidFilter.Enabled = true
				filter.NewPidFilter.Value = true
				filter.NewContFilter.Enabled = true
				filter.NewContFilter.Value = true
				continue
			}
			if operatorAndValues == "!=new" {
				filter.ContFilter.Enabled = true
				filter.ContFilter.Value = true
				filter.NewPidFilter.Enabled = true
				filter.NewPidFilter.Value = true
				filter.NewContFilter.Enabled = true
				filter.NewContFilter.Value = false
				continue
			}
		}

		if strings.HasPrefix("event", filterName) {
			err := parseStringFilter(operatorAndValues, eventFilter)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if filterName == "mntns" {
			err := parseUintFilter(operatorAndValues, filter.MntNSFilter)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if filterName == "pidns" {
			err := parseUintFilter(operatorAndValues, filter.PidNSFilter)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if strings.HasPrefix("pid", filterName) {
			if operatorAndValues == "=new" {
				filter.NewPidFilter.Enabled = true
				filter.NewPidFilter.Value = true
				continue
			}
			if operatorAndValues == "!=new" {
				filter.NewPidFilter.Enabled = true
				filter.NewPidFilter.Value = false
				continue
			}
			err := parseUintFilter(operatorAndValues, filter.PIDFilter)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if strings.HasPrefix("set", filterName) {
			err := parseStringFilter(operatorAndValues, setFilter)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if filterName == "uts" {
			err := parseStringFilter(operatorAndValues, filter.UTSFilter)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if strings.HasPrefix("uid", filterName) {
			err := parseUintFilter(operatorAndValues, filter.UIDFilter)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if strings.HasPrefix("follow", f) {
			filter.Follow = true
			continue
		}

		return tracee.Filter{}, fmt.Errorf("invalid filter option specified, use '--filter help' for more info")
	}

	var err error
	filter.EventsToTrace, err = prepareEventsToTrace(eventFilter, setFilter, eventsNameToID)
	if err != nil {
		return tracee.Filter{}, err
	}

	return filter, nil
}

func parseUintFilter(operatorAndValues string, uintFilter *tracee.UintFilter) error {
	uintFilter.Enabled = true
	if len(operatorAndValues) < 2 {
		return fmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
	}
	valuesString := string(operatorAndValues[1:])
	operatorString := string(operatorAndValues[0])

	if operatorString == "!" {
		if len(operatorAndValues) < 3 {
			return fmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
		}
		operatorString = operatorAndValues[0:2]
		valuesString = operatorAndValues[2:]
	}

	values := strings.Split(valuesString, ",")

	for i := range values {
		val, err := strconv.ParseUint(values[i], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid filter value: %s", values[i])
		}
		if uintFilter.Is32Bit && (val > math.MaxUint32) {
			return fmt.Errorf("filter value is too big: %s", values[i])
		}
		switch operatorString {
		case "=":
			uintFilter.Equal = append(uintFilter.Equal, val)
		case "!=":
			uintFilter.NotEqual = append(uintFilter.NotEqual, val)
		case ">":
			if (uintFilter.Greater == tracee.GreaterNotSetUint) || (val > uintFilter.Greater) {
				uintFilter.Greater = val
			}
		case "<":
			if (uintFilter.Less == tracee.LessNotSetUint) || (val < uintFilter.Less) {
				uintFilter.Less = val
			}
		default:
			return fmt.Errorf("invalid filter operator: %s", operatorString)
		}
	}

	return nil
}

func parseIntFilter(operatorAndValues string, intFilter *tracee.IntFilter) error {
	intFilter.Enabled = true
	if len(operatorAndValues) < 2 {
		return fmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
	}
	valuesString := string(operatorAndValues[1:])
	operatorString := string(operatorAndValues[0])

	if operatorString == "!" {
		if len(operatorAndValues) < 3 {
			return fmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
		}
		operatorString = operatorAndValues[0:2]
		valuesString = operatorAndValues[2:]
	}

	values := strings.Split(valuesString, ",")

	for i := range values {
		val, err := strconv.ParseInt(values[i], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid filter value: %s", values[i])
		}
		if intFilter.Is32Bit && (val > math.MaxInt32) {
			return fmt.Errorf("filter value is too big: %s", values[i])
		}
		switch operatorString {
		case "=":
			intFilter.Equal = append(intFilter.Equal, val)
		case "!=":
			intFilter.NotEqual = append(intFilter.NotEqual, val)
		case ">":
			if (intFilter.Greater == tracee.GreaterNotSetInt) || (val > intFilter.Greater) {
				intFilter.Greater = val
			}
		case "<":
			if (intFilter.Less == tracee.LessNotSetInt) || (val < intFilter.Less) {
				intFilter.Less = val
			}
		default:
			return fmt.Errorf("invalid filter operator: %s", operatorString)
		}
	}

	return nil
}

func parseStringFilter(operatorAndValues string, stringFilter *tracee.StringFilter) error {
	stringFilter.Enabled = true
	if len(operatorAndValues) < 2 {
		return fmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
	}
	valuesString := string(operatorAndValues[1:])
	operatorString := string(operatorAndValues[0])

	if operatorString == "!" {
		if len(operatorAndValues) < 3 {
			return fmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
		}
		operatorString = operatorAndValues[0:2]
		valuesString = operatorAndValues[2:]
	}

	values := strings.Split(valuesString, ",")

	for i := range values {
		switch operatorString {
		case "=":
			stringFilter.Equal = append(stringFilter.Equal, values[i])
		case "!=":
			stringFilter.NotEqual = append(stringFilter.NotEqual, values[i])
		default:
			return fmt.Errorf("invalid filter operator: %s", operatorString)
		}
	}

	return nil
}

func parseBoolFilter(value string, boolFilter *tracee.BoolFilter) error {
	boolFilter.Enabled = true
	boolFilter.Value = false
	if value[0] != '!' {
		boolFilter.Value = true
	}

	return nil
}

func parseArgFilter(filterName string, operatorAndValues string, eventsNameToID map[string]int32, argFilter *tracee.ArgFilter) error {
	argFilter.Enabled = true
	// Event argument filter has the following format: "event.argname=argval"
	// filterName have the format event.argname, and operatorAndValues have the format "=argval"
	splitFilter := strings.Split(filterName, ".")
	if len(splitFilter) != 2 {
		return fmt.Errorf("invalid argument filter format %s%s", filterName, operatorAndValues)
	}
	eventName := splitFilter[0]
	argName := splitFilter[1]

	id, ok := eventsNameToID[eventName]
	if !ok {
		return fmt.Errorf("invalid argument filter event name: %s", eventName)
	}

	eventParams, ok := tracee.EventsIDToParams[id]
	if !ok {
		return fmt.Errorf("invalid argument filter event name: %s", eventName)
	}

	// check if argument name exists for this event
	argFound := false
	for i := range eventParams {
		if eventParams[i].Name == argName {
			argFound = true
			break
		}
	}

	if !argFound {
		return fmt.Errorf("invalid argument filter argument name: %s", argName)
	}

	strFilter := &tracee.StringFilter{
		Equal:    []string{},
		NotEqual: []string{},
	}

	// Treat operatorAndValues as a string filter to avoid code duplication
	err := parseStringFilter(operatorAndValues, strFilter)
	if err != nil {
		return err
	}

	if _, ok := argFilter.Filters[id]; !ok {
		argFilter.Filters[id] = make(map[string]tracee.ArgFilterVal)
	}

	if _, ok := argFilter.Filters[id][argName]; !ok {
		argFilter.Filters[id][argName] = tracee.ArgFilterVal{}
	}

	val := argFilter.Filters[id][argName]

	val.Equal = append(val.Equal, strFilter.Equal...)
	val.NotEqual = append(val.NotEqual, strFilter.NotEqual...)

	argFilter.Filters[id][argName] = val

	return nil
}

func parseRetFilter(filterName string, operatorAndValues string, eventsNameToID map[string]int32, retFilter *tracee.RetFilter) error {
	retFilter.Enabled = true
	// Ret filter has the following format: "event.ret=val"
	// filterName have the format event.retval, and operatorAndValues have the format "=val"
	splitFilter := strings.Split(filterName, ".")
	if len(splitFilter) != 2 || splitFilter[1] != "retval" {
		return fmt.Errorf("invalid retval filter format %s%s", filterName, operatorAndValues)
	}
	eventName := splitFilter[0]

	id, ok := eventsNameToID[eventName]
	if !ok {
		return fmt.Errorf("invalid retval filter event name: %s", eventName)
	}

	if _, ok := retFilter.Filters[id]; !ok {
		retFilter.Filters[id] = tracee.IntFilter{
			Equal:    []int64{},
			NotEqual: []int64{},
			Less:     tracee.LessNotSetInt,
			Greater:  tracee.GreaterNotSetInt,
		}
	}

	intFilter := retFilter.Filters[id]

	// Treat operatorAndValues as an int filter to avoid code duplication
	err := parseIntFilter(operatorAndValues, &intFilter)
	if err != nil {
		return err
	}

	retFilter.Filters[id] = intFilter

	return nil
}
func prepareEventsToTrace(eventFilter *tracee.StringFilter, setFilter *tracee.StringFilter, eventsNameToID map[string]int32) ([]int32, error) {
	eventFilter.Enabled = true
	eventsToTrace := eventFilter.Equal
	excludeEvents := eventFilter.NotEqual
	setsToTrace := setFilter.Equal

	var res []int32
	setsToEvents := make(map[string][]int32)
	isExcluded := make(map[int32]bool)
	for id, event := range tracee.EventsIDToEvent {
		for _, set := range event.Sets {
			setsToEvents[set] = append(setsToEvents[set], id)
		}
	}
	for _, name := range excludeEvents {
		// Handle event prefixes with wildcards
		if strings.HasSuffix(name, "*") {
			found := false
			prefix := name[:len(name)-1]
			for event, id := range eventsNameToID {
				if strings.HasPrefix(event, prefix) {
					isExcluded[id] = true
					found = true
				}
			}
			if !found {
				return nil, fmt.Errorf("invalid event to exclude: %s", name)
			}
		} else {
			id, ok := eventsNameToID[name]
			if !ok {
				return nil, fmt.Errorf("invalid event to exclude: %s", name)
			}
			isExcluded[id] = true
		}
	}
	if len(eventsToTrace) == 0 && len(setsToTrace) == 0 {
		setsToTrace = append(setsToTrace, "default")
	}

	res = make([]int32, 0, len(tracee.EventsIDToEvent))
	for _, name := range eventsToTrace {
		// Handle event prefixes with wildcards
		if strings.HasSuffix(name, "*") {
			var ids []int32
			found := false
			prefix := name[:len(name)-1]
			for event, id := range eventsNameToID {
				if strings.HasPrefix(event, prefix) {
					ids = append(ids, id)
					found = true
				}
			}
			if !found {
				return nil, fmt.Errorf("invalid event to trace: %s", name)
			}
			res = append(res, ids...)
		} else {
			id, ok := eventsNameToID[name]
			if !ok {
				return nil, fmt.Errorf("invalid event to trace: %s", name)
			}
			res = append(res, id)
		}
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

func checkRequiredCapabilities() bool {
	caps, err := getSelfCapabilities()
	if err != nil {
		return false
	}
	return caps.Get(capability.EFFECTIVE, capability.CAP_SYS_ADMIN)
}

func missingKernelConfigOptions() []string {

	requiredConfigOptions := map[uint32]string{
		helpers.CONFIG_BPF:           "y",
		helpers.CONFIG_BPF_SYSCALL:   "y",
		helpers.CONFIG_KPROBE_EVENTS: "y",
		helpers.CONFIG_BPF_EVENTS:    "y",
	}

	kConfig := helpers.KernelConfig{}
	kConfig.InitKernelConfig()

	missing := []string{}

	for requiredOption, setting := range requiredConfigOptions {
		opt, err := kConfig.GetKernelConfigValue(requiredOption)
		if err != nil {
			missing = append(missing, helpers.KernelConfigKeyIDToString[requiredOption])
			continue
		}
		if opt != setting {
			missing = append(missing, helpers.KernelConfigKeyIDToString[requiredOption])
		}
	}
	return missing
}

func getSelfCapabilities() (capability.Capabilities, error) {
	cap, err := capability.NewPid2(0)
	if err != nil {
		return nil, err
	}
	err = cap.Load()
	if err != nil {
		return nil, err
	}
	return cap, nil
}

func fetchFormattedEventParams(eventID int32) string {
	eventParams := tracee.EventsIDToParams[eventID]
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

func printList() {
	padChar, firstPadLen, secondPadLen := " ", 9, 36
	titleHeaderPadFirst := getPad(padChar, firstPadLen)
	titleHeaderPadSecond := getPad(padChar, secondPadLen)

	var b strings.Builder
	b.WriteString("System Calls: " + titleHeaderPadFirst + "Sets:" + titleHeaderPadSecond + "Arguments:\n")
	b.WriteString("____________  " + titleHeaderPadFirst + "____ " + titleHeaderPadSecond + "_________" + "\n\n")
	for i := 0; i < int(tracee.SysEnterEventID); i++ {
		index := int32(i)
		event, ok := tracee.EventsIDToEvent[index]
		if !ok {
			continue
		}
		if event.Sets != nil {
			eventSets := fmt.Sprintf("%-22s %-40s %s\n", event.Name, fmt.Sprintf("%v", event.Sets), fetchFormattedEventParams(index))
			b.WriteString(eventSets)
		} else {
			b.WriteString(event.Name + "\n")
		}
	}
	b.WriteString("\n\nOther Events: " + titleHeaderPadFirst + "Sets:" + titleHeaderPadSecond + "Arguments:\n")
	b.WriteString("____________  " + titleHeaderPadFirst + "____ " + titleHeaderPadSecond + "_________\n\n")
	for i := int(tracee.SysEnterEventID); i < int(tracee.MaxEventID); i++ {
		index := int32(i)
		event := tracee.EventsIDToEvent[index]
		if event.Sets != nil {
			eventSets := fmt.Sprintf("%-22s %-40s %s\n", event.Name, fmt.Sprintf("%v", event.Sets), fetchFormattedEventParams(index))
			b.WriteString(eventSets)
		} else {
			b.WriteString(event.Name + "\n")
		}
	}
	fmt.Println(b.String())
}

// locateFile locates a file named file, or a directory if name is empty, and returns it's full path
// It first tries in the paths given by the dirs, and then a system lookup
func locateFile(file string, dirs []string) string {
	var res string
	for _, dir := range dirs {
		if dir != "" {
			fi, err := os.Stat(filepath.Join(dir, file))
			if err == nil && ((file == "" && fi.IsDir()) || (file != "" && fi.Mode().IsRegular())) {
				return filepath.Join(dir, file)
			}
		}
	}
	if file != "" && res == "" {
		p, _ := exec.LookPath(file)
		if p != "" {
			return p
		}
	}
	return ""
}

// getBPFObject finds or builds ebpf object file and returns it's path
func getBPFObject() (string, error) {
	bpfPath, present := os.LookupEnv("TRACEE_BPF_FILE")
	if present {
		if _, err := os.Stat(bpfPath); os.IsNotExist(err) {
			return "", fmt.Errorf("path given in TRACEE_BPF_FILE doesn't exist!")
		}
		return bpfPath, nil
	}
	bpfObjFileName := fmt.Sprintf("tracee.bpf.%s.%s.o", strings.ReplaceAll(tracee.UnameRelease(), ".", "_"), strings.ReplaceAll(version, ".", "_"))
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	//locations to search for the bpf file, in the following order
	searchPaths := []string{
		filepath.Dir(exePath),
		traceeInstallPath,
	}
	bpfObjFilePath := locateFile(bpfObjFileName, searchPaths)
	if bpfObjFilePath != "" && debug {
		fmt.Printf("found bpf object file at: %s\n", bpfObjFilePath)
	}

	if (bpfObjFilePath == "" && buildPolicy != "never") || buildPolicy == "always" {
		if debug {
			fmt.Printf("attempting to build the bpf object file\n")
		}
		bpfObjInstallPath := filepath.Join(traceeInstallPath, bpfObjFileName)
		err = makeBPFObject(bpfObjInstallPath)
		if err != nil {
			return "", err
		}
		if debug {
			fmt.Printf("successfully built ebpf obj file into: %s\n", bpfObjInstallPath)
		}
		bpfObjFilePath = bpfObjInstallPath
	}

	if bpfObjFilePath == "" {
		return "", fmt.Errorf("could not find or build the bpf object file")
	}
	return bpfObjFilePath, nil
}

// unpackBPFBundle unpacks the bundle into the provided directory
func unpackBPFBundle(dir string) error {
	basePath := "dist/tracee.bpf"
	files, err := bpfBundleInjected.ReadDir(basePath)
	if err != nil {
		return fmt.Errorf("error reading embedded bpf bundle: %s", err.Error())
	}
	for _, f := range files {
		outFile, err := os.Create(filepath.Join(dir, filepath.Base(f.Name())))
		if err != nil {
			return fmt.Errorf("error creating bpf file: %s", err.Error())
		}
		defer outFile.Close()

		f, err := bpfBundleInjected.Open(filepath.Join(basePath, f.Name()))
		if err != nil {
			return fmt.Errorf("error opening bpf bundle file: %s", err.Error())
		}
		defer f.Close()

		if _, err := io.Copy(outFile, f); err != nil {
			return fmt.Errorf("error copying bpf file: %s", err.Error())
		}
	}
	return nil
}

// makeBPFObject builds the ebpf object from source code into the provided path
func makeBPFObject(outFile string) error {
	// drop capabilities for the compilation process
	cap, err := getSelfCapabilities()
	if err != nil {
		return err
	}
	capNew, err := capability.NewPid2(0)
	if err != err {
		return err
	}
	capNew.Clear(capability.BOUNDS)
	err = capNew.Apply(capability.BOUNDS)
	if err != err {
		return err
	}
	defer cap.Apply(capability.BOUNDS)
	dir, err := ioutil.TempDir("", "tracee-make")
	if err != nil {
		return err
	}
	if debug {
		fmt.Printf("building bpf object in: %s\n", dir)
	} else {
		defer os.RemoveAll(dir)
	}
	objFile := filepath.Join(dir, "tracee.bpf.o")
	err = unpackBPFBundle(dir)
	if err != nil {
		return err
	}
	clang := locateFile("clang", []string{os.Getenv("CLANG")})
	if clang == "" {
		return fmt.Errorf("missing compilation dependency: clang")
	}
	cmdVer := exec.Command(clang, "--version")
	verOut, err := cmdVer.CombinedOutput()
	if err != nil {
		return err
	}
	// we are looking for the "version x.y.z" part in the text output
	start := strings.Index(string(verOut), "version") + 8
	end := strings.Index(string(verOut), "\n")
	verStr := string(verOut[start:end])
	verMajor, err := strconv.Atoi(strings.SplitN(verStr, ".", 2)[0])
	if err != nil {
		if debug {
			fmt.Printf("warning: could not detect clang version from: %s", string(verOut))
		}
	} else if verMajor < 9 {
		return fmt.Errorf("detected clang version: %d is older than required minimum version: 9", verMajor)
	}
	llc := locateFile("llc", []string{os.Getenv("LLC")})
	if llc == "" {
		return fmt.Errorf("missing compilation dependency: llc")
	}
	llvmstrip := locateFile("llvm-strip", []string{os.Getenv("LLVM_STRIP")})

	kernelHeaders := locateFile("", []string{os.Getenv("KERN_HEADERS")})
	kernelBuildPath := locateFile("", []string{fmt.Sprintf("/lib/modules/%s/build", tracee.UnameRelease())})
	kernelSourcePath := locateFile("", []string{fmt.Sprintf("/lib/modules/%s/source", tracee.UnameRelease())})
	if kernelHeaders != "" {
		// In case KERN_HEADERS is set, use it for both source/ and build/
		kernelBuildPath = kernelHeaders
		kernelSourcePath = kernelHeaders
	}
	if kernelBuildPath == "" {
		return fmt.Errorf("missing kernel source code compilation dependency")
	}
	// In some distros (e.g. debian, suse), kernel headers are split to build/ and source/
	// while in others (e.g. ubuntu, arch), all headers will be located under build/
	if kernelSourcePath == "" {
		kernelSourcePath = kernelBuildPath
	}
	linuxArch := os.Getenv("ARCH")
	if linuxArch == "" {
		linuxArch = strings.Replace(runtime.GOARCH, "amd64", "x86", 1)
	}

	// from the Makefile:
	// $(CLANG) -S \
	// 	-D__BPF_TRACING__ \
	// 	-D__KERNEL__ \
	// 	-D__TARGET_ARCH_$(linux_arch) \
	// 	-I $(LIBBPF_HEADERS)/bpf \
	// 	-include $(KERN_SRC_PATH)/include/linux/kconfig.h \
	// 	-I $(KERN_SRC_PATH)/arch/$(linux_arch)/include \
	// 	-I $(KERN_SRC_PATH)/arch/$(linux_arch)/include/uapi \
	// 	-I $(KERN_BLD_PATH)/arch/$(linux_arch)/include/generated \
	// 	-I $(KERN_BLD_PATH)/arch/$(linux_arch)/include/generated/uapi \
	// 	-I $(KERN_SRC_PATH)/include \
	// 	-I $(KERN_BLD_PATH)/include \
	// 	-I $(KERN_SRC_PATH)/include/uapi \
	// 	-I $(KERN_BLD_PATH)/include/generated \
	// 	-I $(KERN_BLD_PATH)/include/generated/uapi \
	// 	-I $(BPF_HEADERS) \
	// 	-Wno-address-of-packed-member \
	// 	-Wno-compare-distinct-pointer-types \
	// 	-Wno-deprecated-declarations \
	// 	-Wno-gnu-variable-sized-type-not-at-end \
	// 	-Wno-pointer-sign \
	// 	-Wno-pragma-once-outside-heade \
	// 	-Wno-unknown-warning-option \
	// 	-Wno-unused-value \
	// 	-Wunused \
	// 	-Wall \
	// 	-fno-stack-protector \
	// 	-fno-jump-tables \
	// 	-fno-unwind-tables \
	// 	-fno-asynchronous-unwind-tables \
	// 	-xc \
	// 	-nostdinc \
	// 	-O2 -emit-llvm -c -g $< -o $(@:.o=.ll)
	intermediateFile := strings.Replace(objFile, ".o", ".ll", 1)
	// TODO: validate all files/directories. perhaps using locateFile
	cmd1 := exec.Command(clang,
		"-S",
		"-D__BPF_TRACING__",
		"-D__KERNEL__",
		fmt.Sprintf("-D__TARGET_ARCH_%s", linuxArch),
		fmt.Sprintf("-I%s", dir),
		fmt.Sprintf("-include%s/include/linux/kconfig.h", kernelSourcePath),
		fmt.Sprintf("-I%s/arch/%s/include", kernelSourcePath, linuxArch),
		fmt.Sprintf("-I%s/arch/%s/include/uapi", kernelSourcePath, linuxArch),
		fmt.Sprintf("-I%s/arch/%s/include/generated", kernelBuildPath, linuxArch),
		fmt.Sprintf("-I%s/arch/%s/include/generated/uapi", kernelBuildPath, linuxArch),
		fmt.Sprintf("-I%s/include", kernelSourcePath),
		fmt.Sprintf("-I%s/include", kernelBuildPath),
		fmt.Sprintf("-I%s/include/uapi", kernelSourcePath),
		fmt.Sprintf("-I%s/include/generated", kernelBuildPath),
		fmt.Sprintf("-I%s/include/generated/uapi", kernelBuildPath),
		"-Wno-address-of-packed-member",
		"-Wno-compare-distinct-pointer-types",
		"-Wno-deprecated-declarations",
		"-Wno-gnu-variable-sized-type-not-at-end",
		"-Wno-pointer-sign",
		"-Wno-pragma-once-outside-heade",
		"-Wno-unknown-warning-option",
		"-Wno-unused-value",
		"-Wunused",
		"-Wall",
		"-fno-stack-protector",
		"-fno-jump-tables",
		"-fno-unwind-tables",
		"-fno-asynchronous-unwind-tables",
		"-xc",
		"-nostdinc", "-O2", "-emit-llvm", "-c", "-g", filepath.Join(dir, "tracee.bpf.c"), fmt.Sprintf("-o%s", intermediateFile),
	)
	cmd1.Dir = dir
	if debug {
		fmt.Println(cmd1)
		cmd1.Stdout = os.Stdout
		cmd1.Stderr = os.Stderr
	}
	err = cmd1.Run()
	if err != nil {
		return fmt.Errorf("failed to make BPF object (clang): %v. Try using --debug for more info", err)
	}

	// from Makefile:
	// $(LLC) -march=bpf -filetype=obj -o $@ $(@:.o=.ll)
	cmd2 := exec.Command(llc,
		"-march=bpf",
		"-filetype=obj",
		"-o", objFile,
		intermediateFile,
	)
	cmd2.Dir = dir
	if debug {
		fmt.Println(cmd2)
		cmd2.Stdout = os.Stdout
		cmd2.Stderr = os.Stderr
	}
	err = cmd2.Run()
	if err != nil {
		return fmt.Errorf("failed to make BPF object (llc): %v. Try using --debug for more info", err)
	}

	// from Makefile:
	// -$(LLVM_STRIP) -g $@
	if llvmstrip != "" {
		cmd3 := exec.Command(llvmstrip,
			"-g", objFile,
		)
		cmd3.Dir = dir
		if debug {
			fmt.Println(cmd3)
			cmd3.Stdout = os.Stdout
			cmd3.Stderr = os.Stderr
		}
		err = cmd3.Run()
		if err != nil {
			return fmt.Errorf("failed to make BPF object (llvm-strip): %v. Try using --debug for more info", err)
		}
	}

	if debug {
		fmt.Printf("successfully built ebpf obj file at: %s\n", objFile)
	}
	os.MkdirAll(filepath.Dir(outFile), 0755)
	err = tracee.CopyFileByPath(objFile, outFile)
	if err != nil {
		return err
	}

	return nil
}
