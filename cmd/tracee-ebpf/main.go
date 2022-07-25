package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/aquasecurity/tracee/cmd/tracee-ebpf/flags"
	"github.com/aquasecurity/tracee/cmd/tracee-ebpf/initialize"
	"github.com/aquasecurity/tracee/cmd/tracee-ebpf/internal/debug"
	"github.com/aquasecurity/tracee/cmd/tracee-ebpf/internal/printer"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	cli "github.com/urfave/cli/v2"
)

var traceeInstallPath string
var listenMetrics bool
var metricsAddr string
var enrich bool

var version string

const (
	allowHighCapabilitiesFlag = "allow-high-capabilities"
)

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

			// enable debug mode if debug flag is passed
			if c.Bool("debug") {
				err := debug.Enable()
				if err != nil {
					return fmt.Errorf("failed to start debug mode: %v", err)
				}
			}

			// for the rest of execution, use this debug mode value
			debug := debug.Enabled()

			// OS release information

			OSInfo, err := helpers.GetOSInfo()
			if debug {
				if err != nil {
					fmt.Fprintf(os.Stderr, "OSInfo: warning: os-release file could not be found\n(%v)\n", err) // only to be enforced when BTF needs to be downloaded, later on
					fmt.Fprintf(os.Stdout, "OSInfo: %v: %v\n", helpers.OS_KERNEL_RELEASE, OSInfo.GetOSReleaseFieldValue(helpers.OS_KERNEL_RELEASE))
				} else {
					for k, v := range OSInfo.GetOSReleaseAllFieldValues() {
						fmt.Fprintf(os.Stdout, "OSInfo: %v: %v\n", k, v)
					}
				}
			}

			cfg := tracee.Config{
				PerfBufferSize:     c.Int("perf-buffer-size"),
				BlobPerfBufferSize: c.Int("blob-perf-buffer-size"),
				Debug:              debug,
				OSInfo:             OSInfo,
				ContainersEnrich:   enrich,
			}

			containerRuntimesSlice := c.StringSlice("crs")
			if checkCommandIsHelp(containerRuntimesSlice) {
				fmt.Print(flags.ContainersHelp())
				return nil
			}
			sockets, err := flags.PrepareContainers(containerRuntimesSlice)
			if err != nil {
				return err
			}
			cfg.Sockets = sockets

			cacheSlice := c.StringSlice("cache")
			if checkCommandIsHelp(cacheSlice) {
				fmt.Print(flags.CacheHelp())
				return nil
			}
			cache, err := flags.PrepareCache(cacheSlice)
			if err != nil {
				return err
			}
			cfg.Cache = cache
			if debug && cfg.Cache != nil {
				fmt.Fprintf(os.Stdout, "Cache: cache type is \"%s\"\n", cfg.Cache)
			}

			captureSlice := c.StringSlice("capture")
			if checkCommandIsHelp(captureSlice) {
				fmt.Print(flags.CaptureHelp())
				return nil
			}
			capture, err := flags.PrepareCapture(captureSlice)
			if err != nil {
				return err
			}
			cfg.Capture = &capture

			traceSlice := c.StringSlice("trace")
			if checkCommandIsHelp(traceSlice) {
				fmt.Print(flags.FilterHelp())
				return nil
			}
			filter, err := flags.PrepareFilter(traceSlice)
			if err != nil {
				return err
			}
			cfg.Filter = &filter

			containerMode := (cfg.Filter.ContFilter.Enabled && cfg.Filter.ContFilter.Value) ||
				(cfg.Filter.NewContFilter.Enabled && cfg.Filter.NewContFilter.Value) ||
				cfg.Filter.ContIDFilter.Enabled

			outputSlice := c.StringSlice("output")
			if checkCommandIsHelp(outputSlice) {
				fmt.Print(flags.OutputHelp())
				return nil
			}
			output, printerConfig, err := flags.PrepareOutput(outputSlice)
			if err != nil {
				return err
			}

			printerConfig.ContainerMode = containerMode
			cfg.Output = &output

			// environment capabilities
			err = ensureCapabilities(OSInfo, &cfg, c.Bool(allowHighCapabilitiesFlag))
			if err != nil {
				return err
			}

			// kernel lockdown check
			lockdown, err := helpers.Lockdown()
			if err == nil && lockdown == helpers.CONFIDENTIALITY {
				return fmt.Errorf("kernel lockdown is set to 'confidentiality', can't load eBPF programs")
			}
			if debug {
				fmt.Fprintf(os.Stdout, "OSInfo: Security Lockdown is '%v'\n", lockdown)
			}

			enabled, err := helpers.FtraceEnabled()
			if err != nil {
				return err
			}
			if !enabled {
				fmt.Fprintf(os.Stderr, "ftrace_enabled: warning: ftrace is not enabled, kernel events won't be caught, make sure to enable it by executing echo 1 | sudo tee /proc/sys/kernel/ftrace_enabled")
			}

			// OS kconfig information

			kernelConfig, err := initialize.KernelConfig()
			if err != nil {
				return err
			}

			// decide BTF & BPF files to use based on kconfig, release & environment
			err = initialize.BpfObject(&cfg, kernelConfig, OSInfo, traceeInstallPath, version)
			if err != nil {
				return fmt.Errorf("failed preparing BPF object: %w", err)
			}

			cfg.ChanEvents = make(chan trace.Event, 1000)
			// We buffer the error channel because we may want to publish errors before we start flusing this channel
			cfg.ChanErrors = make(chan error, 10)

			t, err := tracee.New(cfg)
			if err != nil {
				return fmt.Errorf("error creating Tracee: %v", err)
			}

			if listenMetrics {
				err := t.Stats().RegisterPrometheus()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error registering prometheus metrics: %v\n", err)
				} else {
					mux := http.NewServeMux()
					mux.Handle("/metrics", promhttp.Handler())

					go func() {
						if debug {
							fmt.Fprintf(os.Stdout, "Serving metrics endpoint at %s\n", metricsAddr)
						}
						if err := http.ListenAndServe(metricsAddr, mux); err != http.ErrServerClosed {
							fmt.Fprintf(os.Stderr, "Error serving metrics endpoint: %v\n", err)
						}
					}()
				}

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

			printer, err := printer.New(printerConfig)
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
				stats := t.Stats()
				printer.Epilogue(*stats)
				printer.Close()
			}()

			// initialize tracee for running
			err = t.Init()
			if err != nil {
				return fmt.Errorf("error initializing Tracee: %v", err)
			}

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
			&cli.StringSliceFlag{
				Name:    "cache",
				Aliases: []string{"a"},
				Value:   cli.NewStringSlice("none"),
				Usage:   "Control event caching queues. run '--cache help' for more info.",
			},
			&cli.StringSliceFlag{
				Name:  "crs",
				Usage: "Define connected container runtimes. run '--crs help' for more info.",
				Value: cli.NewStringSlice(),
			},
			&cli.IntFlag{
				Name:    "perf-buffer-size",
				Aliases: []string{"b"},
				Value:   1024, // 4 MB of contigous pages
				Usage:   "size, in pages, of the internal perf ring buffer used to submit events from the kernel",
			},
			&cli.IntFlag{
				Name:  "blob-perf-buffer-size",
				Value: 1024, // 4 MB of contigous pages
				Usage: "size, in pages, of the internal perf ring buffer used to send blobs from the kernel",
			},
			&cli.BoolFlag{
				Name:  "debug",
				Value: false,
				Usage: "write verbose debug messages to standard output and retain intermediate artifacts. enabling will output debug messages to stdout, which will likely break consumers which expect to receive machine-readable events from stdout",
			},
			&cli.StringFlag{
				Name:        "install-path",
				Value:       "/tmp/tracee",
				Usage:       "path where tracee will install or lookup it's resources",
				Destination: &traceeInstallPath,
			},
			&cli.BoolFlag{
				Name:        "metrics",
				Usage:       "enable metrics endpoint",
				Destination: &listenMetrics,
				Value:       false,
			},
			&cli.StringFlag{
				Name:        "metrics-addr",
				Usage:       "listening address of the metrics endpoint server",
				Value:       ":3366",
				Destination: &metricsAddr,
			},
			&cli.BoolFlag{
				Name:        "containers",
				Usage:       "enable container info enrichment to events. this feature is experimental and may cause unexpected behavior in the pipeline",
				Destination: &enrich,
			},
			&cli.BoolFlag{
				Name:    allowHighCapabilitiesFlag,
				Aliases: []string{"ahc"},
				Usage:   "allow tracee-ebpf to run with high capabilities, in case that capabilities dropping fails",
				Value:   false,
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

func printList() {
	padChar, firstPadLen, secondPadLen := " ", 9, 36
	titleHeaderPadFirst := getPad(padChar, firstPadLen)
	titleHeaderPadSecond := getPad(padChar, secondPadLen)

	var b strings.Builder
	b.WriteString("System Calls: " + titleHeaderPadFirst + "Sets:" + titleHeaderPadSecond + "Arguments:\n")
	b.WriteString("____________  " + titleHeaderPadFirst + "____ " + titleHeaderPadSecond + "_________" + "\n\n")
	printEventGroup(&b, 0, events.MaxSyscallID)
	printEventGroup(&b, events.Unique32BitSyscallsStartID, events.Unique32BitSyscallsEndID)
	b.WriteString("\n\nOther Events: " + titleHeaderPadFirst + "Sets:" + titleHeaderPadSecond + "Arguments:\n")
	b.WriteString("____________  " + titleHeaderPadFirst + "____ " + titleHeaderPadSecond + "_________\n\n")
	printEventGroup(&b, events.SysEnter, events.MaxCommonID)
	printEventGroup(&b, events.InitNamespaces, events.MaxUserSpace)
	b.WriteString("\n\nNetwork Events: " + titleHeaderPadFirst + "Sets:" + titleHeaderPadSecond + "Arguments:\n")
	b.WriteString("____________  " + titleHeaderPadFirst + "____ " + titleHeaderPadSecond + "_________\n\n")
	printEventGroup(&b, events.NetPacket, events.MaxNetID)
	fmt.Println(b.String())
}

func printEventGroup(b *strings.Builder, firstEventID, lastEventID events.ID) {
	for i := firstEventID; i < lastEventID; i++ {
		event, ok := events.Definitions.GetSafe(i)
		if !ok || event.Internal {
			continue
		}
		if event.Sets != nil {
			eventSets := fmt.Sprintf("%-22s %-40s %s\n", event.Name, fmt.Sprintf("%v", event.Sets), getFormattedEventParams(i))
			b.WriteString(eventSets)
		} else {
			b.WriteString(event.Name + "\n")
		}
	}
}
