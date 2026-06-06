package yaml

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/tracee/common/errfmt"
	k8s "github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
)

// DetectorFormat represents the detected detector file format
type DetectorFormat string

const (
	FormatK8sCRD    DetectorFormat = "k8s"
	FormatPlainYAML DetectorFormat = "plain"
)

// DetectorFile is the structure of the detector file in K8s CRD format
// Uses k8s.DetectorSpec for kubebuilder compatibility
type DetectorFile struct {
	APIVersion string         `yaml:"apiVersion" json:"apiVersion"`
	Kind       string         `yaml:"kind" json:"kind"`
	Metadata   Metadata       `yaml:"metadata" json:"metadata"`
	Spec       k8s.DetectorSpec `yaml:"spec" json:"spec"`
}

// Metadata is the structure of the metadata in the detector file
type Metadata struct {
	Name        string            `yaml:"name" json:"name"`
	Annotations map[string]string `yaml:"annotations" json:"annotations"`
}

// GetDetectorSpecFromCRD extracts the Spec from CRD format and returns YAMLDetectorSpec
// Sets Type field to "detector" for validation compatibility
func GetDetectorSpecFromCRD(file *DetectorFile) *YAMLDetectorSpec {
	if file == nil {
		return nil
	}
	// Convert from DetectorFile (which uses k8s.DetectorSpec) to YAMLDetectorSpec
	return convertK8sSpecToYAMLSpec(&file.Spec)
}

// convertK8sSpecToYAMLSpec converts k8s.DetectorSpec to YAMLDetectorSpec
// Since YAMLDetectorSpec embeds k8s.DetectorSpec and nested types are aliases,
// we just need to copy the embedded struct and set the Type field
func convertK8sSpecToYAMLSpec(k8sSpec *k8s.DetectorSpec) *YAMLDetectorSpec {
	if k8sSpec == nil {
		return nil
	}

	// Since YAMLDetectorSpec embeds k8s.DetectorSpec, we can directly assign the embedded struct
	// All nested types are aliases, so no conversion needed
	yamlSpec := &YAMLDetectorSpec{
		Type: TypeDetector, // Set type for validation (only field not in k8s.DetectorSpec)
	}
	// Copy all fields from k8s.DetectorSpec via embedded struct
	yamlSpec.DetectorSpec = *k8sSpec

	return yamlSpec
}

// peekDetectorFormat detects the format of detector data by examining its structure
// Returns the format type or an error if format cannot be determined
func peekDetectorFormat(data []byte, isJSON bool) (DetectorFormat, error) {
	if isJSON {
		return peekDetectorJSONFormat(data)
	}
	return peekDetectorYAMLFormat(data)
}

// peekDetectorJSONFormat detects the format of JSON detector data
func peekDetectorJSONFormat(data []byte) (DetectorFormat, error) {
	// Check for plain JSON format (type field)
	var typeCheck struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &typeCheck); err == nil {
		normalizedType := strings.TrimSpace(strings.ToLower(typeCheck.Type))
		if normalizedType == TypeDetector {
			return FormatPlainYAML, nil
		}
	}

	// Check for K8s CRD format (apiVersion and kind fields)
	var k8sCheck struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
	}
	if err := json.Unmarshal(data, &k8sCheck); err == nil {
		if k8sCheck.APIVersion == "tracee.aquasec.com/v1beta1" && k8sCheck.Kind == "Detector" {
			return FormatK8sCRD, nil
		}
	}

	// Default to plain format if neither detected (for backward compatibility)
	return FormatPlainYAML, nil
}

// peekDetectorYAMLFormat detects the format of YAML detector data
func peekDetectorYAMLFormat(data []byte) (DetectorFormat, error) {
	// Check for plain YAML format (type field)
	var typeCheck struct {
		Type string `yaml:"type"`
	}
	typeErr := yaml.Unmarshal(data, &typeCheck)
	if typeErr == nil {
		normalizedType := strings.TrimSpace(strings.ToLower(typeCheck.Type))
		if normalizedType == TypeDetector {
			return FormatPlainYAML, nil
		}
	}

	// Check for K8s CRD format (apiVersion and kind fields)
	var k8sCheck struct {
		APIVersion string `yaml:"apiVersion"`
		Kind       string `yaml:"kind"`
	}
	k8sErr := yaml.Unmarshal(data, &k8sCheck)
	if k8sErr == nil {
		if k8sCheck.APIVersion == "tracee.aquasec.com/v1beta1" && k8sCheck.Kind == "Detector" {
			return FormatK8sCRD, nil
		}
	}

	// If neither format detected, return error
	return "", errfmt.Errorf("unable to determine detector format: file must have either 'type: detector' (plain format) or 'apiVersion' and 'kind' fields (K8s CRD)")
}

// readFileData reads file data with size check
func readFileData(filePath string) ([]byte, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	if fileInfo.Size() > MaxYAMLFileSize {
		return nil, fmt.Errorf("detector file too large: %d bytes (max: %d bytes)", fileInfo.Size(), MaxYAMLFileSize)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	return data, nil
}

// ParseCRDFile reads and parses a K8s CRD format detector file
// Returns DetectorFile with k8s.DetectorSpec (for kubebuilder compatibility)
func ParseCRDFile(filePath string) (*DetectorFile, error) {
	data, err := readFileData(filePath)
	if err != nil {
		return nil, err
	}

	var file DetectorFile
	isJSON := strings.HasSuffix(filePath, ".json")
	if isJSON {
		err = json.Unmarshal(data, &file)
	} else {
		err = yaml.Unmarshal(data, &file)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRD detector file: %w", err)
	}

	return &file, nil
}
