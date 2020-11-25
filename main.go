package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
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
			filter, err := prepareFilter(c.StringSlice("filter"))
			if err != nil {
				return err
			}
			cfg := tracee.TraceeConfig{
				EventsToTrace:         events,
				Mode:                  mode,
				Filter:                filter,
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
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Value:   "table",
				Usage:   "output format: table/table-verbose/json/gob/go-template=<path>",
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
				Usage:   "set trace mode, whether to trace processes or containers, and if to trace new, all, or specific processes/container. run '--trace help' for more info",
			},
			&cli.StringSliceFlag{
				Name:    "filter",
				Aliases: []string{"f"},
				Value:   nil,
				Usage:   "set tracing filters for specific fields (such as UID or GID). run '--filter help' for more info.",
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

	uids := []uint32{}

	filterHelp := "\n--filter allows you to specify values to match on for fields of traced events.\n"
	filterHelp += "The following options are currently supported:\n"
	filterHelp += "uid: only trace processes or containers with specified uid(s).\n"
	filterHelp += "\t--filter uid=0                                                | only trace events from uid 0\n"
	filterHelp += "\t--filter uid=0,1000                                           | only trace events from uid 0 or uid 1000\n"
	filterHelp += "\t--filter uid=0 --filter uid=1000                              | only trace events from uid 0 or uid 1000 (same as above)\n"

	if len(filters) == 1 && filters[0] == "help" {
		return tracee.Filter{}, fmt.Errorf(filterHelp)
	}

	for _, f := range filters {
		s := strings.Split(f, "=")
		if len(s) != 2 {
			return tracee.Filter{}, fmt.Errorf(filterHelp)
		}
		if !validFilterOption(s[0]) {
			return tracee.Filter{}, fmt.Errorf("invalid filter: %s\n%s", s[0], filterHelp)
		}

		if s[0] == "uid" {
			values := strings.Split(s[1], ",")
			for _, v := range values {
				uid, err := strconv.ParseUint(v, 10, 32)
				if err != nil {
					return tracee.Filter{}, fmt.Errorf("specified invalid uid: %s", v)
				}
				uids = append(uids, uint32(uid))
			}
		}
	}
	return tracee.Filter{
		UIDs: uids,
	}, nil
}

func validFilterOption(s string) bool {
	validOptions := map[string]bool{
		"uid": true,
	}
	return validOptions[s]
}

func prepareTraceMode(traceString string) (uint32, []int, error) {
	// Set Default mode - all new Processes only
	mode := tracee.ModeProcessNew
	var pidsToTrace []int
	traceHelp := "\n--trace can be the following options:\n"
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
	bpfObjFileName := fmt.Sprintf("tracee.bpf.%s.%s.o", strings.ReplaceAll(tracee.UnameRelease(), ".", "_"), strings.ReplaceAll(version, ".", "_"))
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	//locations to search for the bpf file, in the following order
	searchPaths := []string{
		os.Getenv("TRACEE_BPF_FILE"),
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

	kernelSource := locateFile("", []string{os.Getenv("KERN_SRC"), fmt.Sprintf("/lib/modules/%s/build", tracee.UnameRelease())})
	if kernelSource == "" {
		return fmt.Errorf("missing kernel source code compilation dependency")
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
	// 	-include $(KERN_SRC)/include/linux/kconfig.h \
	// 	-I $(KERN_SRC)/arch/$(linux_arch)/include \
	// 	-I $(KERN_SRC)/arch/$(linux_arch)/include/uapi \
	// 	-I $(KERN_SRC)/arch/$(linux_arch)/include/generated \
	// 	-I $(KERN_SRC)/arch/$(linux_arch)/include/generated/uapi \
	// 	-I $(KERN_SRC)/include \
	// 	-I $(KERN_SRC)/include/uapi \
	// 	-I $(KERN_SRC)/include/generated \
	// 	-I $(KERN_SRC)/include/generated/uapi \
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
		fmt.Sprintf("-include%s/include/linux/kconfig.h", kernelSource),
		fmt.Sprintf("-I%s/arch/%s/include", kernelSource, linuxArch),
		fmt.Sprintf("-I%s/arch/%s/include/uapi", kernelSource, linuxArch),
		fmt.Sprintf("-I%s/arch/%s/include/generated", kernelSource, linuxArch),
		fmt.Sprintf("-I%s/arch/%s/include/generated/uapi", kernelSource, linuxArch),
		fmt.Sprintf("-I%s/include", kernelSource),
		fmt.Sprintf("-I%s/include/uapi", kernelSource),
		fmt.Sprintf("-I%s/include/generated", kernelSource),
		fmt.Sprintf("-I%s/include/generated/uapi", kernelSource),
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
		return err
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
		return err
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
			return err
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
