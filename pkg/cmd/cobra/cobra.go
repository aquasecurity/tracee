package cobra

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/flags/server"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
	"github.com/aquasecurity/tracee/pkg/signatures/signature"
	"github.com/aquasecurity/tracee/types/trace"
)

func GetTraceeRunner(c *cobra.Command, version string) (cmd.Runner, error) {
	var runner cmd.Runner

	// Rego command line flags

	rego, err := flags.PrepareRego(viper.GetStringSlice("rego"))
	if err != nil {
		return runner, err
	}

	// Signature directory command line flags

	sigs, err := signature.Find(
		rego.RuntimeTarget,
		rego.PartialEval,
		viper.GetString("signatures-dir"),
		nil,
		rego.AIO,
	)
	if err != nil {
		return runner, err
	}

	initialize.CreateEventsFromSignatures(events.StartSignatureID, sigs)

	// Initialize a tracee config structure

	cfg := tracee.Config{
		PerfBufferSize:     viper.GetInt("perf-buffer-size"),
		BlobPerfBufferSize: viper.GetInt("blob-perf-buffer-size"),
		ContainersEnrich:   viper.GetBool("containers"),
	}

	// Output command line flags

	output, err := flags.PrepareOutput(viper.GetStringSlice("output"), true)
	if err != nil {
		return runner, err
	}
	cfg.Output = output.TraceeConfig

	// Log command line flags

	logCfg, err := flags.PrepareLogger(viper.GetStringSlice("log"), true)
	if err != nil {
		return runner, err
	}
	logger.Init(logCfg)

	// OS release information

	osInfo, err := helpers.GetOSInfo()
	if err != nil {
		logger.Debugw("OSInfo", "warning: os-release file could not be found", "error", err) // only to be enforced when BTF needs to be downloaded, later on
		logger.Debugw("OSInfo", "os_release_field", helpers.OS_KERNEL_RELEASE, "OS_KERNEL_RELEASE", osInfo.GetOSReleaseFieldValue(helpers.OS_KERNEL_RELEASE))
	} else {
		osInfoSlice := make([]interface{}, 0)
		for k, v := range osInfo.GetOSReleaseAllFieldValues() {
			osInfoSlice = append(osInfoSlice, k.String(), v)
		}
		logger.Debugw("OSInfo", osInfoSlice...)
	}

	cfg.OSInfo = osInfo

	// Container Runtime command line flags

	sockets, err := flags.PrepareContainers(viper.GetStringSlice("crs"))
	if err != nil {
		return runner, err
	}
	cfg.Sockets = sockets

	// Cache command line flags

	cache, err := flags.PrepareCache(viper.GetStringSlice("cache"))
	if err != nil {
		return runner, err
	}
	cfg.Cache = cache
	if cfg.Cache != nil {
		logger.Debugw("Cache", "type", cfg.Cache.String())
	}

	// Capture command line flags - via cobra flag

	captureFlags, err := c.Flags().GetStringSlice("capture")
	if err != nil {
		return runner, err
	}

	capture, err := flags.PrepareCapture(captureFlags, true)
	if err != nil {
		return runner, err
	}
	cfg.Capture = &capture

	// Capabilities command line flags

	capsCfg, err := flags.PrepareCapabilities(viper.GetStringSlice("capabilities"))
	if err != nil {
		return runner, err
	}
	cfg.Capabilities = &capsCfg

	// Policy/Filter command line flags - via cobra flag

	policyFlags, err := c.Flags().GetStringSlice("policy")
	if err != nil {
		return runner, err
	}

	filterFlags, err := c.Flags().GetStringSlice("filter")
	if err != nil {
		return runner, err
	}

	if len(policyFlags) > 0 && len(filterFlags) > 0 {
		return runner, errors.New("policy and filter flags cannot be used together")
	}

	var filterMap flags.FilterMap

	if len(policyFlags) > 0 {
		policies, err := getPolicies(policyFlags)
		if err != nil {
			return runner, err
		}

		filterMap, err = flags.PrepareFilterMapFromPolicies(policies)
		if err != nil {
			return runner, err
		}
	} else {
		filterMap, err = flags.PrepareFilterMapFromCobraFlags(filterFlags)
		if err != nil {
			return runner, err
		}
	}

	policies, err := flags.CreatePolicies(filterMap, true)
	if err != nil {
		return runner, err
	}

	cfg.Policies = policies

	// Container information printer flag

	containerMode := cmd.GetContainerMode(cfg)
	printers := make([]printer.EventPrinter, 0, len(output.PrinterConfigs))
	for _, pConfig := range output.PrinterConfigs {
		pConfig.ContainerMode = containerMode

		p, err := printer.New(pConfig)
		if err != nil {
			return runner, err
		}

		printers = append(printers, p)
	}

	// Check kernel lockdown

	lockdown, err := helpers.Lockdown()
	if err != nil {
		logger.Debugw("OSInfo", "lockdown", err)
	}
	if err == nil && lockdown == helpers.CONFIDENTIALITY {
		return runner, errfmt.Errorf("kernel lockdown is set to 'confidentiality', can't load eBPF programs")
	}

	logger.Debugw("OSInfo", "security_lockdown", lockdown)

	// Check if ftrace is enabled

	enabled, err := helpers.FtraceEnabled()
	if err != nil {
		return runner, err
	}
	if !enabled {
		logger.Errorw("ftrace_enabled: ftrace is not enabled, kernel events won't be caught, make sure to enable it by executing echo 1 | sudo tee /proc/sys/kernel/ftrace_enabled")
	}

	// Pick OS information

	kernelConfig, err := initialize.KernelConfig()
	if err != nil {
		return runner, err
	}

	// Decide BTF & BPF files to use (based in the kconfig, release & environment info)

	err = initialize.BpfObject(&cfg, kernelConfig, osInfo, viper.GetString("install-path"), version)
	if err != nil {
		return runner, errfmt.Errorf("failed preparing BPF object: %v", err)
	}

	cfg.ChanEvents = make(chan trace.Event, 1000)

	// Prepare the server

	httpServer, err := server.PrepareServer(
		viper.GetString(server.ListenEndpointFlag),
		viper.GetBool(server.MetricsEndpointFlag),
		viper.GetBool(server.HealthzEndpointFlag),
		viper.GetBool(server.PProfEndpointFlag),
		viper.GetBool(server.PyroscopeAgentFlag),
	)

	if err != nil {
		return runner, err
	}

	runner.Server = httpServer
	runner.TraceeConfig = cfg
	runner.Printers = printers

	// parse arguments must be enabled if the rule engine is part of the pipeline
	runner.TraceeConfig.Output.ParseArguments = true

	runner.TraceeConfig.EngineConfig = engine.Config{
		Enabled:    true,
		Signatures: sigs,
		// This used to be a flag, we have removed the flag from this binary to test
		// if users do use it or not.
		SignatureBufferSize: 1000,
	}

	return runner, nil
}

func getPolicies(paths []string) ([]flags.PolicyFile, error) {
	policies := make([]flags.PolicyFile, 0)

	for _, path := range paths {
		if path == "" {
			return nil, errfmt.Errorf("policy path cannot be empty")
		}

		path, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}

		fileInfo, err := os.Stat(path)
		if err != nil {
			return nil, err
		}

		if !fileInfo.IsDir() {
			p, err := getPoliciesFromFile(path)
			if err != nil {
				return nil, err
			}
			policies = append(policies, p)

			continue
		}

		files, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}

		for _, file := range files {
			if file.IsDir() {
				continue
			}

			// TODO: support json
			if strings.HasSuffix(file.Name(), ".yaml") ||
				strings.HasSuffix(file.Name(), ".yml") {
				policy, err := getPoliciesFromFile(filepath.Join(path, file.Name()))
				if err != nil {
					return nil, err
				}

				policies = append(policies, policy)
			}
		}
	}

	return policies, nil
}

func getPoliciesFromFile(filePath string) (flags.PolicyFile, error) {
	var p flags.PolicyFile

	data, err := os.ReadFile(filePath)
	if err != nil {
		return p, err
	}

	err = yaml.Unmarshal(data, &p)
	if err != nil {
		return p, err
	}

	return p, nil
}
