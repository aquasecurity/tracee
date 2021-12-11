package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/aquasecurity/libbpfgo/helpers"
	embed "github.com/aquasecurity/tracee"
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/tracee-ebpf/tracee"
	"github.com/syndtr/gocapability/capability"
	cli "github.com/urfave/cli/v2"
)

var debug bool
var traceeInstallPath string
var buildPolicy string

var version string

func main() {
	app := &cli.App{
		Name:    "Tracee",
		Usage:   "Trace OS events and syscalls using eBPF",
		Version: version,
		Action: func(c *cli.Context) error {

			// tracee-ebpf does not suport arguments, only flags
			if c.NArg() > 0 {
				cli.ShowAppHelp(c)
				return nil
			}

			if c.Bool("list") {
				printList()
				return nil
			}

			cfg := tracee.Config{
				PerfBufferSize:     c.Int("perf-buffer-size"),
				BlobPerfBufferSize: c.Int("blob-perf-buffer-size"),
				Debug:              c.Bool("debug"),
			}

			if checkCommandIsHelp(c.StringSlice("capture")) {
				fmt.Print(captureHelp())
			}
			capture, err := prepareCapture(c.StringSlice("capture"))
			if err != nil {
				return err
			}
			cfg.Capture = &capture

			if checkCommandIsHelp(c.StringSlice("trace")) {
				fmt.Print(filterHelp())
				return nil
			}
			filter, err := prepareFilter(c.StringSlice("trace"))
			if err != nil {
				return err
			}
			cfg.Filter = &filter

			containerMode := (cfg.Filter.ContFilter.Enabled && cfg.Filter.ContFilter.Value) ||
				(cfg.Filter.NewContFilter.Enabled && cfg.Filter.NewContFilter.Value)

			if checkCommandIsHelp(c.StringSlice("output")) {
				fmt.Print(outputHelp())
				return nil
			}
			output, printerConfig, err := prepareOutput(c.StringSlice("output"))
			if err != nil {
				return err
			}
			cfg.Output = &output

			// environment capabilities

			selfCap, err := getSelfCapabilities()
			if err != nil {
				return err
			}
			if err = checkRequiredCapabilities(selfCap); err != nil {
				return err
			}

			enabled, err := helpers.FtraceEnabled()
			if err != nil {
				return err
			}
			if !enabled {
				fmt.Fprintf(os.Stderr, "ftrace_enabled: warning: ftrace is not enabled, kernel events won't be caught, make sure to enable it by executing echo 1 | sudo tee /proc/sys/kernel/ftrace_enabled")
			}

			// OS kconfig information
			kernelConfig, err := helpers.InitKernelConfig()
			if err == nil { // do not fail (yet ?) if we cannot init kconfig
				kernelConfig.AddNeeded(helpers.CONFIG_BPF, helpers.BUILTIN)
				kernelConfig.AddNeeded(helpers.CONFIG_BPF_SYSCALL, helpers.BUILTIN)
				kernelConfig.AddNeeded(helpers.CONFIG_KPROBE_EVENTS, helpers.BUILTIN)
				kernelConfig.AddNeeded(helpers.CONFIG_BPF_EVENTS, helpers.BUILTIN)
				missing := kernelConfig.CheckMissing() // do fail if we found os-release file and it is not enough
				if len(missing) > 0 {
					return fmt.Errorf("missing kernel configuration options: %s\n", missing)
				}
			} else {
				if debug {
					fmt.Fprintf(os.Stderr, "KConfig: warning: could not check enabled kconfig features\n(%v)\n", err)
					fmt.Fprintf(os.Stderr, "KConfig: warning: assuming kconfig values, might have unexpected behavior\n")
				}
			}

			// OS release information

			OSInfo, err := helpers.GetOSInfo()
			if err != nil {
				if debug {
					fmt.Fprintf(os.Stderr, "OSInfo: warning: os-release file could not be found\n(%v)\n", err) // only to be enforced when BTF needs to be downloaded, later on
					fmt.Fprintf(os.Stdout, "OSInfo: %v: %v\n", helpers.OS_KERNEL_RELEASE, OSInfo.GetOSReleaseFieldValue(helpers.OS_KERNEL_RELEASE))
				}
			} else if debug {
				for k, v := range OSInfo.GetOSReleaseAllFieldValues() {
					fmt.Fprintf(os.Stdout, "OSInfo: %v: %v\n", k, v)
				}
			}

			// decision making based on different factors from environment

			var d = struct {
				btfenv     bool // external BTF file was provided through env TRACEE_BTF_FILE
				bpfenv     bool // external BPF file was provided through env TRACEE_BPF_FILE
				btfvmlinux bool // running kernel provides embedded BTF vmlinux file
			}{
				// default values

				btfenv:     false,
				bpfenv:     false,
				btfvmlinux: helpers.OSBTFEnabled(),
			}

			// change decisions based on environment

			bpfFilePath, err := checkEnvPath("TRACEE_BPF_FILE")
			if bpfFilePath != "" {
				d.bpfenv = true
			} else if bpfFilePath == "" && err != nil {
				return err
			}
			btfFilePath, err := checkEnvPath("TRACEE_BTF_FILE")
			if btfFilePath != "" {
				d.btfenv = true
			} else if btfFilePath == "" && err != nil {
				return err
			}
			if debug {
				fmt.Printf("BTF: bpfenv = %v, btfenv = %v, vmlinux = %v\n", d.bpfenv, d.btfenv, d.btfvmlinux)
			}

			// BPF related

			var bpfBytes []byte

			// Decisions in order:
			// 1. external BPF file given and BTF (vmlinux or env) exists: always load BPF as CO-RE
			// 2. external BPF file given and no BTF exists: it is a non CO-RE BPF, no need to build
			// 3. no external BPF file given and BTF (vmlinux or env) exists: load embedded BPF as CO-RE
			// 4. no external BPF file given and no BTF exists: build non CO-RE BPF

			if d.bpfenv { // external BPF file given
				if debug {
					fmt.Printf("BPF: using BPF object from environment: %v\n", bpfFilePath)
				}
				if d.btfvmlinux || d.btfenv { // BTF exists: always load BPF as CO-RE
					if d.btfenv { // prefer external BTF over internal vmlinux
						if debug {
							fmt.Printf("BTF: using BTF file from environment: %v\n", btfFilePath)
						}
						cfg.BTFObjPath = btfFilePath
					}
				} // TODO: else { check if ELF is really non CO-RE }
				if bpfBytes, err = ioutil.ReadFile(bpfFilePath); err != nil {
					return err
				}
			} else { // no external BPF file given
				if d.btfvmlinux || d.btfenv { // BTF exists: load embedded BPF as CO-RE
					if debug {
						fmt.Println("BPF: using embedded BPF object")
					}
					if d.btfenv {
						if debug {
							fmt.Printf("BTF: using BTF file from environment: %v\n", btfFilePath)
						}
						cfg.BTFObjPath = btfFilePath
					}
					bpfFilePath = "embedded-core"
					bpfBytes, err = unpackCOREBinary()
				} else { // build non CO-RE BPF
					if debug {
						fmt.Println("BPF: no BTF file was found or provided, building BPF object")
					}
					if bpfFilePath, err = getBPFObjectPath(); err != nil {
						return err
					}
					if bpfBytes, err = ioutil.ReadFile(bpfFilePath); err != nil {
						return err
					}
				}
			}

			cfg.KernelConfig = kernelConfig // avoid having to read kconfig again later
			cfg.BPFObjPath = bpfFilePath
			cfg.BPFObjBytes = bpfBytes

			cfg.ChanEvents = make(chan external.Event)
			cfg.ChanErrors = make(chan error)
			cfg.ChanDone = make(chan struct{})

			t, err := tracee.New(cfg)
			if err != nil {
				return fmt.Errorf("error creating Tracee: %v", err)
			}

			if err := os.MkdirAll(cfg.Capture.OutputPath, 0755); err != nil {
				t.Close()
				return fmt.Errorf("error creating output path: %v", err)
			}
			err = ioutil.WriteFile(path.Join(cfg.Capture.OutputPath, "tracee.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0640)
			if err != nil {
				t.Close()
				return fmt.Errorf("error creating readiness file: %v", err)
			}

			if printerConfig.outFile == nil {
				printerConfig.outFile, err = os.OpenFile(printerConfig.outPath, os.O_WRONLY, 0755)
				if err != nil {
					return err
				}
			}
			if printerConfig.errFile == nil {
				printerConfig.errFile, err = os.OpenFile(printerConfig.errPath, os.O_WRONLY, 0755)
				if err != nil {
					return err
				}
			}

			printer, err := newEventPrinter(printerConfig.kind, containerMode, cfg.Output.RelativeTime, printerConfig.outFile, printerConfig.errFile)
			if err != nil {
				return err
			}

			go func() {
				printer.Preamble()
				for {
					select {
					case event := <-cfg.ChanEvents:
						printer.Print(event)
					case err := <-cfg.ChanErrors:
						printer.Error(err)
					case <-cfg.ChanDone:
						return
					}
				}
			}()

			err = t.Run()

			stats := t.GetStats()
			printer.Epilogue(stats)
			printer.Close()
			return err
		},
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "list",
				Aliases: []string{"l"},
				Value:   false,
				Usage:   "just list traceable events",
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
				Usage:   "control how and where output is printed. run '--output help' for more info.",
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

func checkCommandIsHelp(s []string) bool {
	if len(s) == 1 && s[0] == "help" {
		return true
	}
	return false
}

type printerConfig struct {
	kind    string
	outPath string
	outFile *os.File
	errPath string
	errFile *os.File
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

func checkRequiredCapabilities(caps capability.Capabilities) error {
	if !caps.Get(capability.EFFECTIVE, capability.CAP_SYS_ADMIN) {
		return fmt.Errorf("insufficient privileges to run: missing CAP_SYS_ADMIN")
	}

	if !caps.Get(capability.EFFECTIVE, capability.CAP_IPC_LOCK) {
		return fmt.Errorf("insufficient privileges to run: missing CAP_IPC_LOCK")
	}

	return nil
}

func getSelfCapabilities() (capability.Capabilities, error) {
	selfCap, err := capability.NewPid2(0)
	if err != nil {
		return nil, err
	}
	err = selfCap.Load()
	if err != nil {
		return nil, err
	}
	return selfCap, nil
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

	if filepath.IsAbs(file) {
		_, err := os.Stat(file)
		if err == nil {
			return file
		}
	}

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

func checkEnvPath(env string) (string, error) {
	filePath, _ := os.LookupEnv(env)
	if filePath != "" {
		_, err := os.Stat(filePath)
		if err != nil {
			return "", fmt.Errorf("could not open %s %s", env, filePath)
		}
		return filePath, nil
	}
	return "", nil
}

// getBPFObjectPath finds or builds ebpf object file and returns it's path
func getBPFObjectPath() (string, error) {

	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	//locations to search for the bpf file, in the following order
	searchPaths := []string{
		filepath.Dir(exePath),
		traceeInstallPath,
	}

	release, _ := helpers.UnameRelease()
	bpfObjFileName := fmt.Sprintf("tracee.bpf.%s.%s.o", strings.ReplaceAll(release, ".", "_"), strings.ReplaceAll(version, ".", "_"))
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

func unpackCOREBinary() ([]byte, error) {
	b, err := embed.BPFBundleInjected.ReadFile("dist/tracee.bpf.core.o")
	if err != nil {
		return nil, err
	}

	if debug {
		fmt.Println("unpacked CO:RE bpf object file into memory")
	}

	return b, nil
}

// unpackBPFBundle unpacks the bundle into the provided directory
func unpackBPFBundle(dir string) error {
	basePath := "dist/tracee.bpf"
	files, err := embed.BPFBundleInjected.ReadDir(basePath)
	if err != nil {
		return fmt.Errorf("error reading embedded bpf bundle: %s", err.Error())
	}
	for _, f := range files {
		outFile, err := os.Create(filepath.Join(dir, filepath.Base(f.Name())))
		if err != nil {
			return fmt.Errorf("error creating bpf file: %s", err.Error())
		}
		defer outFile.Close()

		f, err := embed.BPFBundleInjected.Open(filepath.Join(basePath, f.Name()))
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

	clang, err := checkClang()
	if err != nil {
		return err
	}

	llc := locateFile("llc", []string{os.Getenv("LLC")})
	if llc == "" {
		return fmt.Errorf("missing compilation dependency: llc")
	}
	llvmstrip := locateFile("llvm-strip", []string{os.Getenv("LLVM_STRIP")})

	release, err := helpers.UnameRelease()
	if err != nil {
		return err
	}
	kernelHeaders := locateFile("", []string{os.Getenv("KERN_HEADERS")})
	kernelBuildPath := locateFile("", []string{fmt.Sprintf("/lib/modules/%s/build", release)})
	kernelSourcePath := locateFile("", []string{fmt.Sprintf("/lib/modules/%s/source", release)})
	if kernelHeaders != "" {
		// In case KERN_HEADERS is set, use it for both source/ and build/
		kernelBuildPath = kernelHeaders
		kernelSourcePath = kernelHeaders
	}
	if kernelBuildPath == "" {
		return fmt.Errorf("kernel headers could not be found, they are required for bpf compilation if CORE is not enabled. Set KERN_HEADERS to their path.")
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

func checkClang() (string, error) {
	clang := locateFile("clang", []string{os.Getenv("CLANG")})
	if clang == "" {
		return "", fmt.Errorf("missing compilation dependency: clang")
	}
	cmdVer := exec.Command(clang, "--version")
	verOut, err := cmdVer.CombinedOutput()
	if err != nil {
		return "", err
	}
	return clang, checkClangVersion(verOut)
}

func checkClangVersion(verOut []byte) error {
	// we are looking for the "version x.y.z" part in the text output
	re := regexp.MustCompile(`(version)\s\S*`)
	versionString := re.FindString(string(verOut))
	if len(versionString) < 1 {
		return fmt.Errorf("could not detect clang version from: %s", string(verOut))
	}
	verStr := strings.Split(versionString, " ")[1]

	verMajor, _ := strconv.Atoi(strings.SplitN(verStr, ".", 2)[0])
	if verMajor < 12 {
		return fmt.Errorf("detected clang version: %d is older than required minimum version: 12", verMajor)
	}
	return nil
}
