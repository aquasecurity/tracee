package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/base64"
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

	"github.com/aquasecurity/tracee/tracee"
	"github.com/syndtr/gocapability/capability"
	"github.com/urfave/cli/v2"
)

var debug bool
var traceeInstallPath string
var buildPolicy string

// These vars are supposed to be injected at build time
var bpfBundleInjected string
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
			mode, err := prepareTraceMode(c.String("trace"))
			if err != nil {
				return err
			}

			cfg := tracee.TraceeConfig{
				Mode:                  mode,
				DetectOriginalSyscall: c.Bool("detect-original-syscall"),
				ShowExecEnv:           c.Bool("show-exec-env"),
				OutputFormat:          c.String("output"),
				PerfBufferSize:        c.Int("perf-buffer-size"),
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
			filter, err := prepareFilter(c.StringSlice("filter"))
			if err != nil {
				return err
			}
			cfg.Filter = &filter

			if c.Bool("security-alerts") {
				cfg.Filter.EventsToTrace = append(cfg.Filter.EventsToTrace, tracee.MemProtAlertEventID)
			}
			if c.Bool("clear-output-path") {
				os.RemoveAll(cfg.OutputPath)
			}
			bpfFile, err := getBPFObject()
			if err != nil {
				return err
			}
			cfg.BPFObjPath = bpfFile
			if !checkRequiredCapabilities() {
				return fmt.Errorf("Insufficient privileges to run")
			}
			t, err := tracee.New(cfg)
			if err != nil {
				// t is being closed internally
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
			&cli.StringFlag{
				Name:    "trace",
				Aliases: []string{"t"},
				Value:   "new",
				Usage:   "trace mode: new/pidns/follow/all. run '--trace help' for more info",
			},
			&cli.StringSliceFlag{
				Name:    "filter",
				Aliases: []string{"f"},
				Value:   nil,
				Usage:   "set tracing filters for specific fields (such as UID or PID). run '--filter help' for more info.",
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
				Name:    "output",
				Aliases: []string{"o"},
				Value:   "table",
				Usage:   "output format: table/table-verbose/json/gob/go-template=<path>",
			},
			&cli.StringFlag{
				Name:  "output-path",
				Value: "/tmp/tracee/out",
				Usage: "path where tracee will save produced artifacts",
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
				Usage: "capture artifacts that were written, executed or found to be suspicious. captured artifacts will appear in the 'output-path' directory. possible options: 'write'/'exec'/'mem'/'all'. use this flag multiple times to choose multiple capture options",
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
			&cli.BoolFlag{
				Name:        "debug",
				Value:       false,
				Usage:       "write verbose debug messages to stdndard output and retain intermediate artifacts",
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

func prepareFilter(filters []string) (tracee.Filter, error) {
	filterHelp := `
--filter allows you to specify values to match on for fields of traced events.

Numerical filters use the following operators: '=', '!=', '<', '>'
available numerical filters: uid, pid, mntns, pidns

String filters use the following operators: '=', '!='
available string filters: event, set, uts, comm

Boolean filters use the following operator: '!'
available boolean filters: container

Note: some of the above operators have special meanings in different shells.
To 'escape' those operators, please use single quotes, e.g.: 'uid>0'

Examples:
	--filter uid=0                                                | only trace events from uid 0
	--filter mntns=4026531840                                     | only trace events from mntns id 4026531840
	--filter pidns!=4026531836                                    | only trace events from pidns id not equal to 4026531840
	--filter pid=510,1709                                         | only trace events from pid 510 or pid 1709
	--filter pid=510 --filter pid=1709                            | only trace events from pid 510 or pid 1709 (same as above)
	--filter 'uid>0'                                              | only trace events from uids greater than 0
	--filter 'pid>0' --filter 'pid<1000'                          | only trace events from pids between 0 and 1000
	--filter 'uid>0' --filter uid!=1000                           | only trace events from uids greater than 0 but not 1000
	--filter event=execve,open                                    | only trace execve and open events
	--filter set=fs                                               | trace all file-system related events
	--filter set=fs --filter event!=open,openat                   | trace all file-system related events, but not open(at)
	--filter uts!=ab356bc4dd554                                   | don't trace events from uts name ab356bc4dd554
	--filter comm=ls                                              | only trace events from ls command
	--filter container                                            | only trace events from containers
	--filter c                                                    | only trace events from containers (same as above)
	--filter !container                                           | only trace events from the host
	--filter '!c'                                                 | only trace events from the host (same as above)

`

	if len(filters) == 1 && filters[0] == "help" {
		return tracee.Filter{}, fmt.Errorf(filterHelp)
	}

	filter := tracee.Filter{
		UIDFilter: &tracee.UintFilter{
			Equal:    []uint64{},
			NotEqual: []uint64{},
			Less:     tracee.LessNotSet,
			Greater:  tracee.GreaterNotSet,
			Is32Bit:  true,
			Enabled:  false,
		},
		PIDFilter: &tracee.UintFilter{
			Equal:    []uint64{},
			NotEqual: []uint64{},
			Less:     tracee.LessNotSet,
			Greater:  tracee.GreaterNotSet,
			Is32Bit:  true,
			Enabled:  false,
		},
		MntNSFilter: &tracee.UintFilter{
			Equal:    []uint64{},
			NotEqual: []uint64{},
			Less:     tracee.LessNotSet,
			Greater:  tracee.GreaterNotSet,
			Is32Bit:  false,
			Enabled:  false,
		},
		PidNSFilter: &tracee.UintFilter{
			Equal:    []uint64{},
			NotEqual: []uint64{},
			Less:     tracee.LessNotSet,
			Greater:  tracee.GreaterNotSet,
			Is32Bit:  false,
			Enabled:  false,
		},
		UTSFilter: &tracee.StringFilter{
			Equal:    []string{},
			NotEqual: []string{},
			Enabled:  false,
		},
		CommFilter: &tracee.StringFilter{
			Equal:    []string{},
			NotEqual: []string{},
			Enabled:  false,
		},
		ContFilter: &tracee.BoolFilter{
			Value:   false,
			Enabled: false,
		},
		EventsToTrace: []int32{},
	}

	eventFilter := &tracee.StringFilter{Equal: []string{}, NotEqual: []string{}, Enabled: false}
	setFilter := &tracee.StringFilter{Equal: []string{}, NotEqual: []string{}, Enabled: false}

	for _, f := range filters {
		if strings.HasPrefix(f, "uid") {
			err := parseUintFilter(strings.TrimPrefix(f, "uid"), filter.UIDFilter)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if strings.HasPrefix(f, "mntns") {
			err := parseUintFilter(strings.TrimPrefix(f, "mntns"), filter.MntNSFilter)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if strings.HasPrefix(f, "pidns") {
			err := parseUintFilter(strings.TrimPrefix(f, "pidns"), filter.PidNSFilter)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if strings.HasPrefix(f, "pid") {
			err := parseUintFilter(strings.TrimPrefix(f, "pid"), filter.PIDFilter)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if strings.HasPrefix(f, "uts") {
			err := parseStringFilter(strings.TrimPrefix(f, "uts"), filter.UTSFilter)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if strings.HasPrefix(f, "comm") {
			err := parseStringFilter(strings.TrimPrefix(f, "comm"), filter.CommFilter)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if strings.HasPrefix("container", f) || (strings.HasPrefix("!container", f) && len(f) > 1) {
			err := parseBoolFilter(f, filter.ContFilter)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if strings.HasPrefix(f, "event") {
			err := parseStringFilter(strings.TrimPrefix(f, "event"), eventFilter)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		if strings.HasPrefix(f, "set") {
			err := parseStringFilter(strings.TrimPrefix(f, "set"), setFilter)
			if err != nil {
				return tracee.Filter{}, err
			}
			continue
		}

		return tracee.Filter{}, fmt.Errorf("invalid filter option specified, use '--filter help' for more info")
	}

	var err error
	filter.EventsToTrace, err = prepareEventsToTrace(eventFilter, setFilter)
	if err != nil {
		return tracee.Filter{}, err
	}

	return filter, nil
}

func parseUintFilter(operatorAndValues string, uintFilter *tracee.UintFilter) error {
	uintFilter.Enabled = true
	if len(operatorAndValues) < 1 {
		return fmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
	}
	valuesString := string(operatorAndValues[1:])
	operatorString := string(operatorAndValues[0])

	if operatorString == "!" {
		if len(operatorAndValues) < 2 {
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
			if (uintFilter.Greater == tracee.GreaterNotSet) || (val > uintFilter.Greater) {
				uintFilter.Greater = val
			}
		case "<":
			if (uintFilter.Less == tracee.LessNotSet) || (val < uintFilter.Less) {
				uintFilter.Less = val
			}
		default:
			return fmt.Errorf("invalid filter operator: %s", operatorString)
		}
	}

	return nil
}

func parseStringFilter(operatorAndValues string, stringFilter *tracee.StringFilter) error {
	stringFilter.Enabled = true
	if len(operatorAndValues) < 1 {
		return fmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
	}
	valuesString := string(operatorAndValues[1:])
	operatorString := string(operatorAndValues[0])

	if operatorString == "!" {
		if len(operatorAndValues) < 2 {
			return fmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
		}
		operatorString = operatorAndValues[0:2]
		valuesString = operatorAndValues[2:]
	}

	values := strings.Split(valuesString, ",")

	for i := range values {
		if len(values[i]) > 32 {
			return fmt.Errorf("Filtering strings of length bigger than 32 is not supported: %s", values[i])
		}
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

func prepareTraceMode(traceString string) (uint32, error) {
	traceHelp := "\n--trace can be the following options, or a prefix of those:\n"
	traceHelp += "'new'            | Trace new processes\n"
	traceHelp += "'pidns'          | Trace processes from newly created pid namespaces\n"
	traceHelp += "'follow'         | Trace filtered process and all of its children\n"
	traceHelp += "'all'            | Trace all processes\n"
	if traceString == "help" {
		return 0, fmt.Errorf(traceHelp)
	}

	if strings.HasPrefix("new", traceString) {
		return tracee.ModeNew, nil
	}

	if strings.HasPrefix("pidns", traceString) {
		return tracee.ModePidNs, nil
	}

	if strings.HasPrefix("follow", traceString) {
		return tracee.ModeFollow, nil
	}

	if strings.HasPrefix("all", traceString) {
		return tracee.ModeAll, nil
	}

	return 0, fmt.Errorf("invalid trace option specified, use '--trace help' for more info")
}

func prepareEventsToTrace(eventFilter *tracee.StringFilter, setFilter *tracee.StringFilter) ([]int32, error) {
	eventFilter.Enabled = true
	eventsToTrace := eventFilter.Equal
	excludeEvents := eventFilter.NotEqual
	setsToTrace := setFilter.Equal

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
	if len(eventsToTrace) == 0 && len(setsToTrace) == 0 {
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

func checkRequiredCapabilities() bool {
	caps, err := getSelfCapabilities()
	if err != nil {
		return false
	}
	return caps.Get(capability.EFFECTIVE, capability.CAP_SYS_ADMIN)
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

func printList() {
	var b strings.Builder
	b.WriteString("System Calls:              Sets:\n")
	b.WriteString("____________               ____\n\n")
	for i := 0; i < int(tracee.SysEnterEventID); i++ {
		event, ok := tracee.EventsIDToEvent[int32(i)]
		if !ok {
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
	for i := int(tracee.SysEnterEventID); i < int(tracee.MaxEventID); i++ {
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

// unpackBPFBundle unpacks the bundle (tar(gzip(b64))) into the provided directory
func unpackBPFBundle(dir string) error {
	if bpfBundleInjected == "" {
		return fmt.Errorf("missing embedded data")
	}
	b64Reader := base64.NewDecoder(base64.RawStdEncoding, strings.NewReader(bpfBundleInjected))
	gzReader, err := gzip.NewReader(b64Reader)
	if err != nil {
		return err
	}
	tarReader := tar.NewReader(gzReader)
	for true {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			//skip directories
		case tar.TypeReg:
			outFile, err := os.Create(filepath.Join(dir, filepath.Base(header.Name)))
			if err != nil {
				return err
			}
			defer outFile.Close()
			if _, err := io.Copy(outFile, tarReader); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown tar type: %v", header)
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
		return fmt.Errorf("Failed to make BPF object (clang): %v. Try using --debug for more info", err)
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
		return fmt.Errorf("Failed to make BPF object (llc): %v. Try using --debug for more info", err)
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
			return fmt.Errorf("Failed to make BPF object (llvm-strip): %v. Try using --debug for more info", err)
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
