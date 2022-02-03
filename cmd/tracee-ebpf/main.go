package main

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/aquasecurity/libbpfgo/helpers"
	embed "github.com/aquasecurity/tracee"
	"github.com/aquasecurity/tracee/cmd/tracee-ebpf/internal/flags"
	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/tracee-ebpf/tracee"
	"github.com/aquasecurity/tracee/tracee-ebpf/tracee/network_protocols"
	"github.com/syndtr/gocapability/capability"
	cli "github.com/urfave/cli/v2"
)

var debug bool
var traceeInstallPath string

var version string

func main() {
	app := &cli.App{
		Name:    "Tracee",
		Usage:   "Trace OS events and syscalls using eBPF",
		Version: version,
		Action: func(c *cli.Context) error {

			// tracee-ebpf does not support arguments, only flags
			if c.NArg() > 0 {
				return cli.ShowAppHelp(c)
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
				fmt.Print(flags.CaptureHelp())
				return nil
			}
			capture, err := flags.PrepareCapture(c.StringSlice("capture"))
			if err != nil {
				return err
			}
			cfg.Capture = &capture

			if checkCommandIsHelp(c.StringSlice("trace")) {
				fmt.Print(flags.FilterHelp())
				return nil
			}
			filter, err := flags.PrepareFilter(c.StringSlice("trace"))
			if err != nil {
				return err
			}
			cfg.Filter = &filter

			containerMode := (cfg.Filter.ContFilter.Enabled && cfg.Filter.ContFilter.Value) ||
				(cfg.Filter.NewContFilter.Enabled && cfg.Filter.NewContFilter.Value) ||
				cfg.Filter.ContIDFilter.Enabled

			if checkCommandIsHelp(c.StringSlice("output")) {
				fmt.Print(flags.OutputHelp())
				return nil
			}
			output, printerConfig, err := flags.PrepareOutput(c.StringSlice("output"))
			if err != nil {
				return err
			}
			cfg.Output = &output

			// kernel lockdown check
			lockdown, err := helpers.Lockdown()
			if err == nil && lockdown == helpers.CONFIDENTIALITY {
				return fmt.Errorf("kernel lockdown is set to 'confidentiality', can't load eBPF programs.")
			}
			if debug {
				fmt.Fprintf(os.Stdout, "OSInfo: Security Lockdown is '%v'\n", lockdown)
			}

			// environment capabilities
			selfCap, err := capabilities.Self()
			if err != nil {
				return err
			}
			if err = capabilities.CheckRequired(selfCap, []capability.Cap{capability.CAP_IPC_LOCK, capability.CAP_SYS_ADMIN}); err != nil {
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

			// decide BTF & BPF files to use based on kconfig, release & environment
			err = prepareBpfObject(&cfg, kernelConfig, OSInfo)
			if err != nil {
				return fmt.Errorf("failed preparing BPF object: %w", err)
			}

			cfg.ChanEvents = make(chan external.Event)
			cfg.ChanErrors = make(chan error)

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

			if printerConfig.OutFile == nil {
				printerConfig.OutFile, err = os.OpenFile(printerConfig.OutPath, os.O_WRONLY, 0755)
				if err != nil {
					return err
				}
			}
			if printerConfig.ErrFile == nil {
				printerConfig.ErrFile, err = os.OpenFile(printerConfig.ErrPath, os.O_WRONLY, 0755)
				if err != nil {
					return err
				}
			}

			printer, err := newEventPrinter(printerConfig.Kind, containerMode, cfg.Output.RelativeTime, printerConfig.OutFile, printerConfig.ErrFile)
			if err != nil {
				return err
			}

			// create a context that is cancelled by SIGINT/SIGTERM
			ctx := context.Background()
			ctx, cancel := context.WithCancel(ctx)
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
			defer func() {
				signal.Stop(sig)
				cancel()
			}()
			go func() {
				select {
				case <-sig:
					cancel()
				case <-ctx.Done():
				}
			}()

			go func() {
				printer.Preamble()
				for {
					select {
					case event := <-cfg.ChanEvents:
						printer.Print(event)
					case err := <-cfg.ChanErrors:
						printer.Error(err)
					case <-ctx.Done():
						return
					}
				}
			}()

			// always print stats before exiting
			defer func() {
				stats := t.GetStats()
				printer.Epilogue(stats)
				printer.Close()
			}()

			// run until ctx is cancelled by signal
			return t.Run(ctx)
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
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func prepareBpfObject(config *tracee.Config, kConfig *helpers.KernelConfig, OSInfo *helpers.OSInfo) error {
	var d = struct {
		btfenv     bool
		bpfenv     bool
		btfvmlinux bool
	}{
		btfenv:     false,
		bpfenv:     false,
		btfvmlinux: helpers.OSBTFEnabled(),
	}

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

	var tVersion, kVersion string
	var bpfBytes []byte
	var unpackBTFFile string

	// Decision ordering:

	// (1) BPF file given & BTF (vmlinux or env) exists: always load BPF as CO-RE
	// (2) BPF file given & if no BTF exists: it is a non CO-RE BPF

	if d.bpfenv {
		if debug {
			fmt.Printf("BPF: using BPF object from environment: %v\n", bpfFilePath)
		}
		if d.btfvmlinux || d.btfenv { // (1)
			if d.btfenv {
				if debug {
					fmt.Printf("BTF: using BTF file from environment: %v\n", btfFilePath)
				}
				config.BTFObjPath = btfFilePath
			}
		} // else {} (2)
		if bpfBytes, err = ioutil.ReadFile(bpfFilePath); err != nil {
			return err
		}

		goto out
	}

	// (3) no BPF file given & BTF (vmlinux or env) exists: load embedded BPF as CO-RE

	if d.btfvmlinux || d.btfenv { // (3)
		if debug {
			fmt.Println("BPF: using embedded BPF object")
		}
		if d.btfenv {
			if debug {
				fmt.Printf("BTF: using BTF file from environment: %v\n", btfFilePath)
			}
			config.BTFObjPath = btfFilePath
		}
		bpfFilePath = "embedded-core"
		bpfBytes, err = unpackCOREBinary()
		if err != nil {
			return fmt.Errorf("could not unpack embedded CO-RE eBPF object: %v", err)
		}

		goto out
	}

	// (4) no BPF file given & no BTF available: check embedded BTF files

	unpackBTFFile = filepath.Join(traceeInstallPath, "/tracee.btf")
	err = unpackBTFHub(unpackBTFFile, OSInfo)

	if err == nil {
		if debug {
			fmt.Printf("BTF: using BTF file from embedded btfhub: %v\n", unpackBTFFile)
		}
		config.BTFObjPath = unpackBTFFile
		bpfFilePath = "embedded-core"
		bpfBytes, err = unpackCOREBinary()
		if err != nil {
			return fmt.Errorf("could not unpack embedded CO-RE eBPF object: %v", err)
		}

		goto out
	}

	// (5) no BPF file given & no BTF available & no embedded BTF: non CO-RE BPF

	tVersion = strings.ReplaceAll(version, "\"", "")
	tVersion = strings.ReplaceAll(tVersion, ".", "_")
	kVersion = OSInfo.GetOSReleaseFieldValue(helpers.OS_KERNEL_RELEASE)
	kVersion = strings.ReplaceAll(kVersion, ".", "_")

	bpfFilePath = fmt.Sprintf("%s/tracee.bpf.%s.%s.o", traceeInstallPath, kVersion, tVersion)
	if debug {
		fmt.Printf("BPF: no BTF file was found or provided\n")
		fmt.Printf("BPF: trying non CO-RE eBPF at %s\n", bpfFilePath)
	}
	if bpfBytes, err = ioutil.ReadFile(bpfFilePath); err != nil {
		return err
	}

out:
	config.KernelConfig = kConfig
	config.BPFObjPath = bpfFilePath
	config.BPFObjBytes = bpfBytes

	return nil
}

func checkCommandIsHelp(s []string) bool {
	if len(s) == 1 && s[0] == "help" {
		return true
	}
	return false
}

func getFormattedEventParams(eventID int32) string {
	eventParams := tracee.EventsDefinitions[eventID].Params
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
	printEventGroup(&b, 0, int(tracee.SysEnterEventID))
	printEventGroup(&b, tracee.Unique32BitSyscallsStartID, int(tracee.Unique32BitSyscallsEndID))
	b.WriteString("Network Events: " + titleHeaderPadFirst + "Sets:" + titleHeaderPadSecond + "Arguments:\n")
	b.WriteString("____________  " + titleHeaderPadFirst + "____ " + titleHeaderPadSecond + "_________" + "\n\n")
	printEventGroup(&b, int(network_protocols.NetPacket), int(network_protocols.MaxNetEventID))
	b.WriteString("\n\nOther Events: " + titleHeaderPadFirst + "Sets:" + titleHeaderPadSecond + "Arguments:\n")
	b.WriteString("____________  " + titleHeaderPadFirst + "____ " + titleHeaderPadSecond + "_________\n\n")
	printEventGroup(&b, int(tracee.SysEnterEventID), int(tracee.MaxCommonEventID))
	printEventGroup(&b, int(tracee.InitNamespacesEventID), int(tracee.MaxUserSpaceEventID))
	fmt.Println(b.String())
}

func printEventGroup(b *strings.Builder, firstEventID, lastEventID int) {
	for i := firstEventID; i < lastEventID; i++ {
		index := int32(i)
		event, ok := tracee.EventsDefinitions[index]
		if !ok {
			continue
		}
		if event.Sets != nil {
			eventSets := fmt.Sprintf("%-22s %-40s %s\n", event.Name, fmt.Sprintf("%v", event.Sets), getFormattedEventParams(index))
			b.WriteString(eventSets)
		} else {
			b.WriteString(event.Name + "\n")
		}
	}
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

// unpackBTFHub unpacks tailored, to the compiled eBPF object, BTF files for kernel supported by BTFHub
func unpackBTFHub(outFilePath string, OSInfo *helpers.OSInfo) error {
	var btfFilePath string

	osId := OSInfo.GetOSReleaseFieldValue(helpers.OS_ID)
	versionId := strings.Replace(OSInfo.GetOSReleaseFieldValue(helpers.OS_VERSION_ID), "\"", "", -1)
	kernelRelease := OSInfo.GetOSReleaseFieldValue(helpers.OS_KERNEL_RELEASE)
	arch := OSInfo.GetOSReleaseFieldValue(helpers.OS_ARCH)

	if err := os.MkdirAll(filepath.Dir(outFilePath), 0); err != nil {
		return fmt.Errorf("could not create temp dir: %s", err.Error())
	}

	btfFilePath = fmt.Sprintf("dist/btfhub/%s/%s/%s/%s.btf", osId, versionId, arch, kernelRelease)
	btfFile, err := embed.BPFBundleInjected.Open(btfFilePath)
	if err != nil {
		return fmt.Errorf("error opening embedded btfhub file: %s", err.Error())
	}
	defer btfFile.Close()

	outFile, err := os.Create(outFilePath)
	if err != nil {
		return fmt.Errorf("could not create btf file: %s", err.Error())
	}
	defer outFile.Close()

	if _, err := io.Copy(outFile, btfFile); err != nil {
		return fmt.Errorf("error copying embedded btfhub file: %s", err.Error())

	}

	return nil
}
