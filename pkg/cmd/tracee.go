package cmd

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
	"github.com/aquasecurity/tracee/pkg/cmd/debug"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/server"
	"github.com/aquasecurity/tracee/types/trace"

	cli "github.com/urfave/cli/v2"
)

func Run(ctx context.Context, c *cli.Context, traceeConfig tracee.Config, printerConfig printer.Config) error {
	// Create Tracee Singleton

	t, err := tracee.New(traceeConfig)
	if err != nil {
		return fmt.Errorf("error creating Tracee: %v", err)
	}

	// Decide if HTTP server should be started

	if server.ShouldStart(c) {
		httpServer := server.New(c.String(server.ListenEndpointFlag))

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

	// Configure the events printer

	printer, err := printer.New(printerConfig)
	if err != nil {
		return err
	}

	// Create a context (cancelled by SIGINT/SIGTERM)

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

	// Print the preamble

	go func() {
		printer.Preamble()
		for {
			select {
			case event := <-traceeConfig.ChanEvents:
				printer.Print(event)
			case err := <-traceeConfig.ChanErrors:
				printer.Error(err)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Print statistics at the end

	defer func() {
		stats := t.Stats()
		printer.Epilogue(*stats)
		printer.Close()
	}()

	// Initialize tracee

	err = t.Init()
	if err != nil {
		return fmt.Errorf("error initializing Tracee: %v", err)
	}

	return t.Run(ctx) // return when context is cancelled by signal

}

func GetTraceeAndPrinterConfig(c *cli.Context, version string) (tracee.Config, printer.Config, error) {
	// Initialize a tracee config structure
	cfg := tracee.Config{
		PerfBufferSize:     c.Int("perf-buffer-size"),
		BlobPerfBufferSize: c.Int("blob-perf-buffer-size"),
		ContainersEnrich:   c.Bool("containers"),
	}

	if c.Bool("debug") {
		if err := debug.Enable(); err != nil {
			return cfg, printer.Config{}, fmt.Errorf("failed to start debug mode: %v", err)
		}

		cfg.Debug = debug.Enabled()
	}

	// OS release information
	OSInfo, err := helpers.GetOSInfo()
	if err != nil {
		// only to be enforced when BTF needs to be downloaded, later on
		logger.Debug("osinfo: warning: os-release file could not be found", "error", err)
		logger.Debug(
			"osinfo",
			"os_realease_field", helpers.OS_KERNEL_RELEASE,
			"OS_KERNEL_RELEASE", OSInfo.GetOSReleaseFieldValue(helpers.OS_KERNEL_RELEASE),
		)
	} else {
		for k, v := range OSInfo.GetOSReleaseAllFieldValues() {
			logger.Debug("osinfo", "OSReleaseField", k, "OS_KERNEL_RELEASE", v)
		}
	}
	cfg.OSInfo = OSInfo

	// Container Runtime command line flags

	sockets, err := flags.PrepareContainers(c.StringSlice("crs"))
	if err != nil {
		return cfg, printer.Config{}, err
	}
	cfg.Sockets = sockets

	// Cache command line flags

	cache, err := flags.PrepareCache(c.StringSlice("cache"))
	if err != nil {
		return cfg, printer.Config{}, err
	}

	cfg.Cache = cache
	if cfg.Cache != nil {
		logger.Debug("cache", "type", cfg.Cache.String())
	}

	// Capture command line flags

	capture, err := flags.PrepareCapture(c.StringSlice("capture"))
	if err != nil {
		return cfg, printer.Config{}, err
	}
	cfg.Capture = &capture

	// Capabilities command line flags

	capsCfg, err := flags.PrepareCapabilities(c.StringSlice("capabilities"))
	if err != nil {
		return cfg, printer.Config{}, err
	}
	cfg.Capabilities = &capsCfg

	// Filtering (trace) command line flags

	filter, err := flags.PrepareFilter(c.StringSlice("trace"))
	if err != nil {
		return cfg, printer.Config{}, err
	}
	cfg.Filter = &filter

	// Check if container mode is enabled

	containerMode := (cfg.Filter.ContFilter.Enabled() && cfg.Filter.ContFilter.Value()) ||
		(cfg.Filter.NewContFilter.Enabled() && cfg.Filter.NewContFilter.Value()) ||
		cfg.Filter.ContIDFilter.Enabled()

	// Output command line flags

	output, printerConfig, err := flags.PrepareOutput(c.StringSlice("output"))
	if err != nil {
		return cfg, printer.Config{}, err
	}

	printerConfig.ContainerMode = containerMode
	cfg.Output = &output

	// Check kernel lockdown

	lockdown, err := helpers.Lockdown()
	if err == nil && lockdown == helpers.CONFIDENTIALITY {
		return cfg, printer.Config{}, fmt.Errorf("kernel lockdown is set to 'confidentiality', can't load eBPF programs")
	}
	logger.Debug("osinfo", "security_lockdown", lockdown)

	// Check if ftrace is enabled

	enabled, err := helpers.FtraceEnabled()
	if err != nil {
		return cfg, printer.Config{}, err
	}
	if !enabled {
		logger.Error("ftrace_enabled: ftrace is not enabled, kernel events won't be caught, make sure to enable it by executing echo 1 | sudo tee /proc/sys/kernel/ftrace_enabled")
	}

	// Pick OS information

	kernelConfig, err := initialize.KernelConfig()
	if err != nil {
		return cfg, printer.Config{}, err
	}

	// Decide BTF & BPF files to use (based in the kconfig, release & environment info)
	traceeInstallPath := c.String("install-path")
	err = initialize.BpfObject(&cfg, kernelConfig, OSInfo, traceeInstallPath, version)
	if err != nil {
		return cfg, printer.Config{}, fmt.Errorf("failed preparing BPF object: %w", err)
	}

	cfg.ChanEvents = make(chan trace.Event, 1000)
	cfg.ChanErrors = make(chan error, 10) // buffer to allow next errors without blocking

	return cfg, printerConfig, nil
}

func PrintEventList(printRulesSet bool) {
	padChar, firstPadLen, secondPadLen := " ", 9, 36
	titleHeaderPadFirst := getPad(padChar, firstPadLen)
	titleHeaderPadSecond := getPad(padChar, secondPadLen)

	var b strings.Builder
	if printRulesSet {
		b.WriteString("Events: " + titleHeaderPadFirst + "Sets:" + titleHeaderPadSecond + "Arguments:\n")
		b.WriteString("____________  " + titleHeaderPadFirst + "____ " + titleHeaderPadSecond + "_________" + "\n\n")
		printEventGroup(&b, events.StartRulesID, events.MaxRulesID)
	}
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
