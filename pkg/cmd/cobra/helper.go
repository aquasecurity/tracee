package cobra

import (
	"fmt"
	"os"

	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/k8s"
	k8sapi "github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
	yamldetectors "github.com/aquasecurity/tracee/pkg/detectors/yaml"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/policy/v1beta1"
)

func createPoliciesFromK8SPolicy(policies []k8sapi.PolicyInterface, detectors []detection.EventDetector) ([]*policy.Policy, error) {
	policyScopeMap, policyEventsMap, err := flags.PrepareFilterMapsFromPolicies(policies, detectors)
	if err != nil {
		return nil, err
	}

	return flags.CreatePolicies(policyScopeMap, policyEventsMap)
}

func createPoliciesFromPolicyFiles(policyFlags []string, detectors []detection.EventDetector) ([]*policy.Policy, error) {
	policyFiles, err := v1beta1.PoliciesFromPaths(policyFlags)
	if err != nil {
		return nil, err
	}

	policyScopeMap, policyEventsMap, err := flags.PrepareFilterMapsFromPolicies(policyFiles, detectors)
	if err != nil {
		return nil, err
	}

	return flags.CreatePolicies(policyScopeMap, policyEventsMap)
}

func createPoliciesFromCLIFlags(scopeFlags, eventFlags []string, detectors []detection.EventDetector) ([]*policy.Policy, error) {
	policyScopeMap, err := flags.PrepareScopeMapFromFlags(scopeFlags)
	if err != nil {
		return nil, err
	}

	policyEventsMap, err := flags.PrepareEventMapFromFlags(eventFlags, detectors)
	if err != nil {
		return nil, err
	}

	return flags.CreatePolicies(policyScopeMap, policyEventsMap)
}

// createDetectorsFromK8SCRDs converts K8s detector CRDs to internal detector format
// It loads lists from mounted ConfigMap file if available
func createDetectorsFromK8SCRDs(k8sDetectors []k8sapi.DetectorInterface) ([]detection.EventDetector, error) {
	var allDetectors []detection.EventDetector

	// Load lists from mounted ConfigMap file
	listsMap := make(map[string][]string)
	listsPath := k8s.GetListsFilePath()
	listsData, err := os.ReadFile(listsPath)
	if err != nil {
		// File not found is not an error - just use empty lists
		logger.Debugw("lists file not found, using empty lists", "path", listsPath, "error", err)
	} else {
		// Parse lists from file data
		parsedLists, err := yamldetectors.ParseListsFromConfigMap(string(listsData))
		if err != nil {
			logger.Debugw("failed to parse lists from file", "path", listsPath, "error", err)
		} else {
			listsMap = parsedLists
			logger.Debugw("loaded lists from file", "path", listsPath, "count", len(listsMap))
		}
	}

	// Convert each K8s detector to internal format
	for _, k8sDetector := range k8sDetectors {
		// Convert k8s.DetectorSpec to YAMLDetectorSpec
		k8sSpec := k8sDetector.GetSpec()
		if k8sSpec == nil {
			logger.Debugw("skipping detector with nil spec", "detector", k8sDetector.GetName())
			continue
		}

		// Convert using the same function used for file-based CRD parsing
		yamlSpec := convertK8sSpecToYAMLSpec(k8sSpec)
		if yamlSpec == nil {
			logger.Debugw("skipping detector with invalid spec", "detector", k8sDetector.GetName())
			continue
		}

		// Validate the spec (using lists if available)
		source := fmt.Sprintf("k8s://%s", k8sDetector.GetName())
		if err := yamldetectors.ValidateSpec(yamlSpec, listsMap, source); err != nil {
			logger.Debugw("skipping invalid detector from K8s", "detector", k8sDetector.GetName(), "error", err)
			continue
		}

		// Convert to DetectorDefinition
		def, err := yamldetectors.ToDetectorDefinition(yamlSpec)
		if err != nil {
			logger.Debugw("failed to convert detector definition", "detector", k8sDetector.GetName(), "error", err)
			continue
		}

		// Validate the definition
		if err := yamldetectors.ValidateDefinition(def); err != nil {
			logger.Debugw("skipping detector with invalid definition", "detector", k8sDetector.GetName(), "error", err)
			continue
		}

		// Create the detector
		detector, err := yamldetectors.NewDetector(def, yamlSpec, listsMap, source)
		if err != nil {
			logger.Debugw("failed to create detector", "detector", k8sDetector.GetName(), "error", err)
			continue
		}

		allDetectors = append(allDetectors, detector)
	}

	return allDetectors, nil
}

// convertK8sSpecToYAMLSpec converts k8s.DetectorSpec to YAMLDetectorSpec
// This mirrors the function in detector_file.go but is needed here for K8s API conversion
func convertK8sSpecToYAMLSpec(k8sSpec *k8sapi.DetectorSpec) *yamldetectors.YAMLDetectorSpec {
	if k8sSpec == nil {
		return nil
	}

	// Since YAMLDetectorSpec embeds k8s.DetectorSpec, we can directly assign the embedded struct
	// All nested types are aliases, so no conversion needed
	yamlSpec := &yamldetectors.YAMLDetectorSpec{
		Type: yamldetectors.TypeDetector, // Set type for validation (only field not in k8s.DetectorSpec)
	}
	// Copy all fields from k8s.DetectorSpec via embedded struct
	yamlSpec.DetectorSpec = *k8sSpec

	return yamlSpec
}
