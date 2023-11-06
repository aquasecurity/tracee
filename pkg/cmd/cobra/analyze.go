package cobra

import (
	"errors"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/flags/server"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/producer"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
	"github.com/aquasecurity/tracee/pkg/signatures/signature"
	"github.com/aquasecurity/tracee/types/detect"
)

func GetTraceeAnalyzeRunner(c *cobra.Command, version string) (cmd.Runner, error) {
	var runner cmd.Runner

	// Log command line flags

	// Logger initialization must be the first thing to be done,
	// so all other packages can use it
	logCfg, err := flags.PrepareLogger(viper.GetStringSlice("log"), true)
	if err != nil {
		return runner, err
	}
	logger.Init(logCfg)

	// Rego command line flags

	rego, err := flags.PrepareRego(viper.GetStringSlice("rego"))
	if err != nil {
		return runner, err
	}

	// Signature directory command line flags

	sigs, err := signature.Find(
		rego.RuntimeTarget,
		rego.PartialEval,
		viper.GetStringSlice("signatures-dir"),
		nil,
		rego.AIO,
	)
	if err != nil {
		return runner, err
	}

	initialize.CreateEventsFromSignatures(events.StartSignatureID, sigs)

	// Initialize a tracee config structure

	cfg := config.Config{
		PerfBufferSize:     viper.GetInt("perf-buffer-size"),
		BlobPerfBufferSize: viper.GetInt("blob-perf-buffer-size"),
		NoContainersEnrich: viper.GetBool("no-containers"),
		Analyze:            true,
		Capture:            &config.CaptureConfig{},
	}

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

	// Process Tree command line flags

	procTree, err := flags.PrepareProcTree(viper.GetStringSlice("proctree"))
	if err != nil {
		return runner, err
	}
	cfg.ProcTree = procTree

	// Capabilities command line flags

	capsCfg, err := flags.PrepareCapabilities(viper.GetStringSlice("capabilities"))
	if err != nil {
		return runner, err
	}
	cfg.Capabilities = &capsCfg

	// Policy/Filter command line flags - via cobra flag

	policyFlags, err := c.Flags().GetStringArray("policy")
	if err != nil {
		return runner, err
	}

	scopeFlags, err := c.Flags().GetStringArray("scope")
	if err != nil {
		return runner, err
	}

	eventFlags, err := c.Flags().GetStringArray("events")
	if err != nil {
		return runner, err
	}

	if len(policyFlags) > 0 && len(scopeFlags) > 0 {
		return runner, errors.New("policy and scope flags cannot be used together")
	}
	if len(policyFlags) > 0 && len(eventFlags) > 0 {
		return runner, errors.New("policy and event flags cannot be used together")
	}

	var policies *policy.Policies

	if len(policyFlags) > 0 {
		policies, err = createPoliciesFromPolicyFiles(policyFlags)
		if err != nil {
			return runner, err
		}
	} else {
		policies, err = createPoliciesFromCLIFlags(scopeFlags, eventFlags)
		if err != nil {
			return runner, err
		}
	}

	cfg.Policies = policies

	// Output command line flags
	output, err := flags.PrepareOutput(viper.GetStringSlice("output"), true)
	if err != nil {
		return runner, err
	}
	cfg.Output = output.TraceeConfig

	// Create printer
	p, err := printer.NewBroadcast(output.PrinterConfigs, cmd.GetContainerMode(cfg))
	if err != nil {
		return runner, err
	}

	// Input command line flags
	input, err := flags.PrepareInput(viper.GetString("input"))
	if err != nil {
		return runner, err
	}
	inputProducer, err := producer.New(input)

	// Prepare the server

	httpServer, err := server.PrepareHTTPServer(
		viper.GetString(server.HTTPListenEndpointFlag),
		viper.GetBool(server.MetricsEndpointFlag),
		viper.GetBool(server.HealthzEndpointFlag),
		viper.GetBool(server.PProfEndpointFlag),
		viper.GetBool(server.PyroscopeAgentFlag),
	)
	if err != nil {
		return runner, err
	}

	grpcServer, err := flags.PrepareGRPCServer(viper.GetString(server.GRPCListenEndpointFlag))
	if err != nil {
		return runner, err
	}

	runner.HTTPServer = httpServer
	runner.GRPCServer = grpcServer
	runner.TraceeConfig = cfg
	runner.Printer = p
	runner.Producer = inputProducer

	runner.TraceeConfig.EngineConfig = engine.Config{
		Enabled:    true,
		Signatures: sigs,
		// This used to be a flag, we have removed the flag from this binary to test
		// if users do use it or not.
		SignatureBufferSize: 1000,
		DataSources:         []detect.DataSource{},
	}

	return runner, nil
}
