package cobra

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aquasecurity/tracee/common/environment"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize/sigs"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/detectors"
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

	logFlags, err := flags.GetFlagsFromViper(flags.LoggingFlag)
	if err != nil {
		return runner, err
	}

	loggerConfig, err := flags.PrepareLogger(logFlags)
	if err != nil {
		return runner, err
	}
	logger.Init(loggerConfig.GetLoggingConfig())

	// Signature directory command line flags

	signatures, dataSources, err := signature.Find(viper.GetStringSlice("signatures-dir"), nil)
	if err != nil {
		return runner, err
	}

	sigs.CreateEventsFromSignatures(events.StartSignatureID, signatures)

	// Get YAML detector search directories from config or CLI
	var yamlDetectorDirs []string
	if viper.IsSet(flags.YAMLDirFlag) {
		// Config file format: detectors.yaml-dir
		yamlDetectorDirs = viper.GetStringSlice(flags.YAMLDirFlag)
	} else if viper.IsSet(flags.DetectorsFlag) {
		// CLI format: --detectors yaml-dir=/path/to/dir
		detectorsFlags, err := flags.GetFlagsFromViper(flags.DetectorsFlag)
		if err != nil {
			return runner, err
		}
		detectorsConfig, err := flags.PrepareDetectors(detectorsFlags)
		if err != nil {
			return runner, err
		}
		yamlDetectorDirs = detectorsConfig.YAMLDirs
	}

	// Pre-register detector events in events.Core before policy initialization
	// This allows the policy manager to select detector events just like regular events
	allDetectors := detectors.CollectAllDetectors(yamlDetectorDirs)
	_, err = detectors.CreateEventsFromDetectors(events.StartDetectorID, allDetectors)
	if err != nil {
		return runner, fmt.Errorf("failed to create detector events: %w", err)
	}

	buffersFlags, err := flags.GetFlagsFromViper(flags.BuffersFlag)
	if err != nil {
		return runner, err
	}
	buffers, err := flags.PrepareBuffers(buffersFlags)
	if err != nil {
		return runner, err
	}

	// Initialize a tracee config structure

	cfg := config.Config{
		Buffers: buffers.GetInternalConfig(),
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

	enrichmentFlags, err := flags.GetFlagsFromViper(flags.EnrichmentFlag)
	if err != nil {
		return runner, err
	}

	enrichmentConfig, err := flags.PrepareEnrichment(enrichmentFlags)
	if err != nil {
		return runner, err
	}

	sockets, err := enrichmentConfig.GetRuntimeSockets()
	if err != nil {
		return runner, err
	}
	cfg.Sockets = sockets
	cfg.EnrichmentEnabled = enrichmentConfig.Container.Enabled
	cfg.CgroupFSPath = enrichmentConfig.Container.Cgroupfs.Path
	cfg.CgroupFSForce = enrichmentConfig.Container.Cgroupfs.Force

	// Stores command line flags
	storesFlags, err := flags.GetFlagsFromViper(flags.StoresFlag)
	if err != nil {
		return runner, err
	}

	stores, err := flags.PrepareStores(storesFlags)
	if err != nil {
		return runner, err
	}

	cfg.ProcessStore = stores.GetProcessStoreConfig()
	cfg.DNSStore = stores.GetDNSStoreConfig()

	// Artifacts command line flags - via viper

	artifactsFlags, err := flags.GetFlagsFromViper(flags.ArtifactsFlag)
	if err != nil {
		return runner, err
	}

	artifactsConfig, err := flags.PrepareArtifacts(artifactsFlags)
	if err != nil {
		return runner, err
	}
	capture := artifactsConfig.GetCapture()
	cfg.Capture = &capture

	// Capabilities command line flags

	capFlags, err := flags.GetFlagsFromViper("capabilities")
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

	// Output
	containerFilterEnabled := func() bool {
		for _, p := range initialPolicies {
			if p.ContainerFilterEnabled() {
				return true
			}
		}

		return false
	}

	outputFlags, err := flags.GetFlagsFromViper("output")
	if err != nil {
		return runner, err
	}

	containerMode := cmd.GetContainerMode(
		containerFilterEnabled(), cfg.EnrichmentEnabled)

	output, err := flags.PrepareOutput(outputFlags, containerMode)
	if err != nil {
		return runner, err
	}

	cfg.Output = output

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
	runtimeFlags, err := flags.GetFlagsFromViper(flags.RuntimeFlag)
	if err != nil {
		return runner, err
	}
	runtimeConfig, err := flags.PrepareRuntime(runtimeFlags)
	if err != nil {
		return runner, err
	}

	err = initialize.BpfObject(&cfg, kernelConfig, osInfo, runtimeConfig.Workdir, version)
	if err != nil {
		return runner, errfmt.Errorf("failed preparing BPF object: %v", err)
	}

	// Prepare the server

	serverFlags, err := flags.GetFlagsFromViper("server")
	if err != nil {
		return runner, err
	}
	serverConfig, err := flags.PrepareServer(serverFlags)
	if err != nil {
		return runner, err
	}

	runner.HTTP = serverConfig.GetHTTPServer()
	runner.GRPC = serverConfig.GetGRPCServer()

	if runner.HTTP != nil {
		cfg.MetricsEnabled = runner.HTTP.IsMetricsEnabled()
		cfg.HealthzEnabled = runner.HTTP.IsHealthzEnabled()
	}

	runner.TraceeConfig = cfg
	runner.Workdir = runtimeConfig.Workdir

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

	runner.TraceeConfig.DetectorConfig = config.DetectorConfig{
		Detectors:      allDetectors,
		YAMLSearchDirs: yamlDetectorDirs,
	}

	return runner, nil
}
