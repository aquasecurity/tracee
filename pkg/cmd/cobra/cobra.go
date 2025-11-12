package cobra

import (
	"errors"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aquasecurity/tracee/common/environment"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize/sigs"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/k8s"
	"github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
	"github.com/aquasecurity/tracee/pkg/signatures/signature"
	"github.com/aquasecurity/tracee/types/detect"
)

// selectSignaturesBasedOnPolicies determines which signatures should be loaded based on user policies
func selectSignaturesBasedOnPolicies(availableSignatures []detect.Signature, policies []*policy.Policy) []detect.Signature {
	// If no policies are configured, load no signatures
	if len(policies) == 0 {
		logger.Debugw("No policies configured, loading no signatures")
		return []detect.Signature{}
	}

	// Create a set of all signature event names required by policies
	requiredEventNames := make(map[string]struct{})
	for _, p := range policies {
		for eventID := range p.Rules {
			eventDef := events.Core.GetDefinitionByID(eventID)
			if eventDef.IsSignature() {
				requiredEventNames[eventDef.GetName()] = struct{}{}
			}
		}
	}

	// If no signature events are required, don't load any signatures
	if len(requiredEventNames) == 0 {
		logger.Debugw("No signature events required by policies, loading no signatures")
		return []detect.Signature{}
	}

	// Iterate through available signatures and select those whose EventName is required
	selectedSignatures := []detect.Signature{}
	for _, sig := range availableSignatures {
		metadata, err := sig.GetMetadata()
		if err != nil {
			logger.Errorw("Failed to get signature metadata", "error", err)
			continue
		}

		// Check if this signature's EventName is required by any policy
		if _, required := requiredEventNames[metadata.EventName]; required {
			selectedSignatures = append(selectedSignatures, sig)
		}
	}

	logger.Debugw("Selected signatures based on policies",
		"total_available", len(availableSignatures),
		"selected", len(selectedSignatures),
		"required_events", len(requiredEventNames))

	return selectedSignatures
}

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

	signaturesFlags, err := flags.PrepareSignatures(viper.GetStringSlice("signatures"))
	if err != nil {
		return runner, err
	}

	signatures, dataSources, err := signature.Find(signaturesFlags.SearchPaths, nil)
	if err != nil {
		return runner, err
	}

	sigs.CreateEventsFromSignatures(events.StartSignatureID, signatures)

	buffersFlag, err := GetFlagsFromViper(flags.BuffersFlag)
	if err != nil {
		return runner, err
	}
	buffers, err := flags.PrepareBuffers(buffersFlag)
	if err != nil {
		return runner, err
	}

	// Initialize a tracee config structure

	cfg := config.Config{
		PerfBufferSize:             buffers.EventsSize,
		BlobPerfBufferSize:         buffers.BlobSize,
		ControlPlanePerfBufferSize: buffers.ControlPlaneSize,
		PipelineChannelSize:        buffers.PipelineSize,
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

	// Container command line flags

	enrichFlags, err := GetFlagsFromViper(flags.EnrichFlag)
	if err != nil {
		return runner, err
	}

	enrichment, err := flags.PrepareEnrichment(enrichFlags)
	if err != nil {
		return runner, err
	}

	sockets, err := enrichment.GetRuntimeSockets()
	if err != nil {
		return runner, err
	}
	cfg.Sockets = sockets
	cfg.NoContainersEnrich = enrichment.ContainerEnabled
	cfg.CgroupFSPath = enrichment.ContainerCgroupPath

	// TODO: are removing this?
	// cfg.CgroupFSForce = enrichment.CgroupfsForce

	// Stores command line flags
	storesFlags, err := GetFlagsFromViper("stores")
	if err != nil {
		return runner, err
	}

	stores, err := flags.PrepareStores(storesFlags)
	if err != nil {
		return runner, err
	}
	cfg.DNSCacheConfig = stores.DNS
	cfg.ProcTree = stores.Process

	// Capture command line flags - via cobra flag

	captureFlags, err := c.Flags().GetStringArray("capture")
	if err != nil {
		return runner, err
	}

	capture, err := flags.NPrepareCapture(captureFlags, true)
	if err != nil {
		return runner, err
	}
	cfg.Capture = &config.CaptureConfig{
		Exec:   capture.Executable,
		Mem:    capture.MemoryRegions,
		Bpf:    capture.BpfPrograms,
		Module: capture.KernelModules,
		Net: config.PcapsConfig{
			CaptureSingle:    capture.Network.Single,
			CaptureProcess:   capture.Network.Process,
			CaptureContainer: capture.Network.Container,
			CaptureCommand:   capture.Network.Command,
			CaptureFiltered:  capture.Network.Filtered,
			CaptureLength:    capture.Network.Length,
		},
		FileWrite: config.FileCaptureConfig{
			Capture:    capture.FileWrite.Enabled,
			PathFilter: capture.FileWrite.PathFilter,
			// TypeFilter: config.CaptureRegularFiles,
		},
		FileRead: config.FileCaptureConfig{
			Capture:    capture.FileRead.Enabled,
			PathFilter: capture.FileRead.PathFilter,
			// TypeFilter: config.CaptureRegularFiles,
		},
		OutputPath: capture.Output.Path,
	}

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

	output, err := flags.PrepareOutput(outputFlags)
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
	generalFlags, err := GetFlagsFromViper("general")
	if err != nil {
		return runner, err
	}
	generalConfig, err := flags.PrepareGeneral(generalFlags)
	if err != nil {
		return runner, err
	}

	err = initialize.BpfObject(&cfg, kernelConfig, osInfo, generalConfig.Workdir, version)
	if err != nil {
		return runner, errfmt.Errorf("failed preparing BPF object: %v", err)
	}

	// Prepare the server

	serverFlag, err := GetFlagsFromViper("server")
	if err != nil {
		return runner, err
	}
	serverRunner, err := flags.PrepareServer(serverFlag)
	if err != nil {
		return runner, err
	}

	runner.HTTP = serverRunner.HTTP
	runner.GRPC = serverRunner.GRPC
	runner.TraceeConfig = cfg
	runner.Printer = p
	runner.Workdir = generalConfig.Workdir

	if runner.HTTP != nil {
		cfg.MetricsEnabled = runner.HTTP.IsMetricsEnabled()
	}

	noSignaturesMode := viper.GetBool("no-signatures")
	if noSignaturesMode {
		logger.Debugw("No-signatures mode enabled, using same signature selection as normal mode for fair comparison")
	}

	runner.TraceeConfig.EngineConfig = engine.Config{
		Mode:                engine.ModeSingleBinary,
		NoSignatures:        noSignaturesMode,
		AvailableSignatures: signatures,
		SelectedSignatures:  selectSignaturesBasedOnPolicies(signatures, initialPolicies),
		DataSources:         dataSources,
	}

	return runner, nil
}
