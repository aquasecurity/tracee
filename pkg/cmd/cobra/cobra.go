package cobra

import (
	"errors"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/flags/server"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize/sigs"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/k8s"
	"github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
	"github.com/aquasecurity/tracee/pkg/signatures/signature"
	"github.com/aquasecurity/tracee/pkg/utils/environment"
)

func GetTraceeRunner(c *cobra.Command, version string) (cmd.Runner, error) {
	var runner cmd.Runner

	// Log command line flags

	// Logger initialization must be the first thing to be done,
	// so all other packages can use

	logFlags, err := GetFlagsFromViper("log")
	if err != nil {
		return runner, err
	}

	logCfg, err := flags.PrepareLogger(logFlags, true)
	if err != nil {
		return runner, err
	}
	logger.Init(logCfg)

	// Signature directory command line flags

	signatures, dataSources, err := signature.Find(viper.GetStringSlice("signatures-dir"), nil)
	if err != nil {
		return runner, err
	}

	sigNameToEventId := sigs.CreateEventsFromSignatures(events.StartSignatureID, signatures)

	// Initialize a tracee config structure

	cfg := config.Config{
		PerfBufferSize:      viper.GetInt("perf-buffer-size"),
		BlobPerfBufferSize:  viper.GetInt("blob-perf-buffer-size"),
		PipelineChannelSize: viper.GetInt("pipeline-channel-size"),
		NoContainersEnrich:  viper.GetBool("no-containers"),
	}

	// OS release information

	osInfo, err := environment.GetOSInfo()
	if err != nil {
		logger.Debugw("OSInfo", "warning: os-release file could not be found", "error", err) // only to be enforced when BTF needs to be downloaded, later on
		logger.Debugw("OSInfo", "os_release_field", environment.OS_KERNEL_RELEASE, "OS_KERNEL_RELEASE", osInfo.GetOSReleaseFieldValue(environment.OS_KERNEL_RELEASE))
	} else {
		osInfoSlice := make([]interface{}, 0)
		for k, v := range osInfo.GetOSReleaseAllFieldValues() {
			osInfoSlice = append(osInfoSlice, k.String(), v)
		}
		logger.Debugw("OSInfo", osInfoSlice...)
	}

	cfg.OSInfo = osInfo

	// Container Runtime command line flags

	if !cfg.NoContainersEnrich {
		criFlags, err := GetFlagsFromViper("cri")
		if err != nil {
			return runner, err
		}

		sockets, err := flags.PrepareContainers(criFlags)
		if err != nil {
			return runner, err
		}
		cfg.Sockets = sockets
	}

	// Cache command line flags

	cacheFlags, err := GetFlagsFromViper("cache")
	if err != nil {
		return runner, err
	}

	cache, err := flags.PrepareCache(cacheFlags)
	if err != nil {
		return runner, err
	}
	cfg.Cache = cache
	if cfg.Cache != nil {
		logger.Debugw("Cache", "type", cfg.Cache.String())
	}

	// Process Tree command line flags

	procTreeFlags, err := GetFlagsFromViper("proctree")
	if err != nil {
		return runner, err
	}

	procTree, err := flags.PrepareProcTree(procTreeFlags)
	if err != nil {
		return runner, err
	}
	cfg.ProcTree = procTree

	// DNS Cache command line flags

	dnsCacheFlags, err := GetFlagsFromViper("dnscache")
	if err != nil {
		return runner, err
	}

	dnsCache, err := flags.PrepareDnsCache(dnsCacheFlags)
	if err != nil {
		return runner, err
	}

	cfg.DNSCacheConfig = dnsCache

	// Capture command line flags - via cobra flag

	captureFlags, err := c.Flags().GetStringArray("capture")
	if err != nil {
		return runner, err
	}

	capture, err := flags.PrepareCapture(captureFlags, true)
	if err != nil {
		return runner, err
	}
	cfg.Capture = &capture

	// Capabilities command line flags

	capFlags, err := GetFlagsFromViper("capabilities")
	if err != nil {
		return runner, err
	}

	capsCfg, err := flags.PrepareCapabilities(capFlags)
	if err != nil {
		return runner, err
	}
	cfg.Capabilities = &capsCfg

	// Policy/Filter command line flags - via cobra flag

	policyFlags, err := c.Flags().GetStringArray("policy")
	if err != nil {
		return runner, err
	}

	// Scope command line flags - via cobra flag

	scopeFlags, err := c.Flags().GetStringArray("scope")
	if err != nil {
		return runner, err
	}
	if len(policyFlags) > 0 && len(scopeFlags) > 0 {
		return runner, errors.New("policy and scope flags cannot be used together")
	}

	// Events command line flags - via cobra flag

	eventFlags, err := c.Flags().GetStringArray("events")
	if err != nil {
		return runner, err
	}
	if len(policyFlags) > 0 && len(eventFlags) > 0 {
		return runner, errors.New("policy and event flags cannot be used together")
	}

	// Try to get policies from kubernetes CRD, policy files and CLI in that order

	var k8sPolicies []v1beta1.PolicyInterface
	var initialPolicies []*policy.Policy

	k8sClient, err := k8s.New()
	if err == nil {
		k8sPolicies, err = k8sClient.GetPolicy(c.Context())
	}
	if err != nil {
		logger.Debugw("kubernetes cluster", "error", err)
	}
	if len(k8sPolicies) > 0 {
		logger.Debugw("using policies from kubernetes crd")
		initialPolicies, err = createPoliciesFromK8SPolicy(k8sPolicies)
	} else if len(policyFlags) > 0 {
		logger.Debugw("using policies from --policy flag")
		initialPolicies, err = createPoliciesFromPolicyFiles(policyFlags)
	} else {
		logger.Debugw("using policies from --scope and --events flag")
		initialPolicies, err = createPoliciesFromCLIFlags(scopeFlags, eventFlags)
	}
	if err != nil {
		return runner, err
	}

	ps := make([]interface{}, 0, len(initialPolicies))
	for _, p := range initialPolicies {
		ps = append(ps, p)
	}
	cfg.InitialPolicies = ps

	// Output command line flags

	outputFlags, err := GetFlagsFromViper("output")
	if err != nil {
		return runner, err
	}

	output, err := flags.PrepareOutput(outputFlags, true)
	if err != nil {
		return runner, err
	}
	cfg.Output = output.TraceeConfig

	// Create printer

	containerFilterEnabled := func() bool {
		for _, p := range initialPolicies {
			if p.ContainerFilterEnabled() {
				return true
			}
		}

		return false
	}

	p, err := printer.NewBroadcast(
		output.PrinterConfigs,
		cmd.GetContainerMode(containerFilterEnabled(), cfg.NoContainersEnrich),
	)
	if err != nil {
		return runner, err
	}

	// Check kernel lockdown

	lockdown, err := environment.Lockdown()
	if err != nil {
		logger.Debugw("OSInfo", "lockdown", err)
	}
	if err == nil && lockdown == environment.CONFIDENTIALITY {
		return runner, errfmt.Errorf("kernel lockdown is set to 'confidentiality', can't load eBPF programs")
	}

	logger.Debugw("OSInfo", "security_lockdown", lockdown)

	// Check if ftrace is enabled

	enabled, err := environment.FtraceEnabled()
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

	traceeInstallPath := viper.GetString("install-path")
	err = initialize.BpfObject(&cfg, kernelConfig, osInfo, traceeInstallPath, version)
	if err != nil {
		return runner, errfmt.Errorf("failed preparing BPF object: %v", err)
	}

	// Prepare the server

	serverFlag, err := GetFlagsFromViper("server")
	if err != nil {
		return runner, err
	}
	server, err := server.PrepareServer(serverFlag)
	if err != nil {
		return runner, err
	}

	runner.HTTPServer = server.HTTPServer
	runner.GRPCServer = server.GRPCServer
	runner.TraceeConfig = cfg
	runner.Printer = p
	runner.InstallPath = traceeInstallPath

	runner.TraceeConfig.EngineConfig = engine.Config{
		Enabled:          true,
		SigNameToEventID: sigNameToEventId,
		Signatures:       signatures,
		// This used to be a flag, we have removed the flag from this binary to test
		// if users do use it or not.
		SignatureBufferSize: 1000,
		DataSources:         dataSources,
	}

	return runner, nil
}
