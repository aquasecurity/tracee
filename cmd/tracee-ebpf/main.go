package main

import (
	"context"
	"fmt"
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
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/server"
	"github.com/aquasecurity/tracee/types/trace"

	cli "github.com/urfave/cli/v2"
)

var traceeInstallPath string
var enrich bool
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

			// enable debug mode if debug flag is passed
			if c.Bool("debug") {
				err := debug.Enable()
				if err != nil {
					return fmt.Errorf("failed to start debug mode: %v", err)
				}
			}

			// for the rest of execution, use this debug mode value
			debug := debug.Enabled()

			// Avoiding to override package-level logger
			// when it's already set by logger environment variables
			if !logger.IsSetFromEnv() {
				// Logger Setup
				logger.Init(
					&logger.LoggerConfig{
						Writer:    os.Stderr,
						Level:     logger.InfoLevel,
						Encoder:   logger.NewJSONEncoder(logger.NewProductionConfig().EncoderConfig),
						Aggregate: false,
					},
				)
			}

			// OS release information

			OSInfo, err := helpers.GetOSInfo()
			if err != nil {
				logger.Debug("osinfo: warning: os-release file could not be found", "error", err) // only to be enforced when BTF needs to be downloaded, later on
				logger.Debug("osinfo", "os_realease_field", helpers.OS_KERNEL_RELEASE, "OS_KERNEL_RELEASE", OSInfo.GetOSReleaseFieldValue(helpers.OS_KERNEL_RELEASE))
			} else {
				for k, v := range OSInfo.GetOSReleaseAllFieldValues() {
					logger.Debug("osinfo", "OSReleaseField", k, "OS_KERNEL_RELEASE", v)
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
			if cfg.Cache != nil {
				logger.Debug("cache", "type", cfg.Cache.String())
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

			capsCfgSlice := c.StringSlice("caps")
			if checkCommandIsHelp(capsCfgSlice) {
				fmt.Print(flags.CapabilitiesHelp())
				return nil
			}
			capsCfg, err := flags.PrepareCapsConfig(capsCfgSlice)
			if err != nil {
				return err
			}

			// environment capabilities
			err = ensureInitCapabilities(OSInfo, &cfg, &capsCfg)
			if err != nil {
				return err
			}

			// kernel lockdown check
			lockdown, err := helpers.Lockdown()
			if err == nil && lockdown == helpers.CONFIDENTIALITY {
				return fmt.Errorf("kernel lockdown is set to 'confidentiality', can't load eBPF programs")
			}
			logger.Debug("osinfo", "security_lockdown", lockdown)

			enabled, err := helpers.FtraceEnabled()
			if err != nil {
				return err
			}
			if !enabled {
				logger.Error("ftrace_enabled: ftrace is not enabled, kernel events won't be caught, make sure to enable it by executing echo 1 | sudo tee /proc/sys/kernel/ftrace_enabled")
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

			if server.ShouldStart(c) {
				httpServer := server.New(c.String(server.ListenEndpointFlag), debug)

				if c.Bool(server.MetricsEndpointFlag) {
					err := t.Stats().RegisterPrometheus()
					if err != nil {
						logger.Error("registering prometheus metrics", "error", err)
					} else {
						httpServer.EnableMetricsEndpoint()
					}
				}

				if c.Bool(server.HealthzEndpointFlag) {
					httpServer.EnableHealthzEndpoint()
				}

				if c.Bool(server.PProfEndpointFlag) {
					httpServer.EnablePProfEndpoint()
				}

				go httpServer.Start()
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

			ensureRuntimeCapabilities(OSInfo, &cfg, &capsCfg)

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
				Name:  server.MetricsEndpointFlag,
				Usage: "enable metrics endpoint",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  server.HealthzEndpointFlag,
				Usage: "enable healthz endpoint",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  server.PProfEndpointFlag,
				Usage: "enables pprof endpoints",
				Value: false,
			},
			&cli.StringFlag{
				Name:  server.ListenEndpointFlag,
				Usage: "listening address of the metrics endpoint server",
				Value: ":3366",
			},
			&cli.BoolFlag{
				Name:        "containers",
				Usage:       "enable container info enrichment to events. this feature is experimental and may cause unexpected behavior in the pipeline",
				Destination: &enrich,
			},
			&cli.StringSliceFlag{
				Name:  flags.CapsMainFlag,
				Usage: fmt.Sprintf("control tracee capabilities dropping functionality. Run '--%s help' for more info", flags.CapsMainFlag),
				Value: cli.NewStringSlice(),
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		logger.Fatal("app", "error", err)
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
			eventSets := fmt.Sprintf("%-28s %-40s %s\n", event.Name, fmt.Sprintf("%v", event.Sets), getFormattedEventParams(i))
			b.WriteString(eventSets)
		} else {
			b.WriteString(event.Name + "\n")
		}
	}
}
