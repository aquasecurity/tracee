package celsig

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/detect"
)

var (
	// extensions known file extensions that hold definition of CEL signatures.
	extensions = []string{"cel", "yml", "yaml"}
)

const (
	KindSignaturesConfig = "SignaturesConfig"
	APIVersionV1Alpha1   = "tracee.aquasecurity.github.io/v1alpha1"
)

// SignaturesConfig represents multiple CEL signature definitions that are
// typically loaded from a configuration YAML file.
type SignaturesConfig struct {
	// Kind indicates type of config loaded from a YAML file.
	Kind string `yaml:"kind"`

	// APIVersion is used to version config properties.
	APIVersion string `yaml:"apiVersion"`

	// Signatures defines CEL SignatureConfig.
	Signatures []SignatureConfig `yaml:"signatures"`
}

// SignatureConfig represents CEL signature definition that's typically loaded
// from a configuration YAML file.
type SignatureConfig struct {
	// Metadata represents signature metadata.
	Metadata detect.SignatureMetadata `yaml:"metadata"`

	// EventSelectors to dispatch events only to these signatures that know how
	// to evaluate them.
	EventSelectors []detect.SignatureEventSelector `yaml:"eventSelectors"`

	// Expression is a CEL expression that is used to evaluate events.
	// To indicate a possible threat the Expression must evaluate to `true`,
	// otherwise event is considered innocent.
	Expression string `yaml:"expression"`
}

// NewConfigFromFile loads CEL SignaturesConfig from the specified file.
func NewConfigFromFile(filePath string) (SignaturesConfig, error) {
	config := SignaturesConfig{}
	file, err := os.Open(filePath)
	if err != nil {
		return SignaturesConfig{}, fmt.Errorf("failed opening CEL signature config file: %s: %w", filePath, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()
	decoder := yaml.NewDecoder(file)

	err = decoder.Decode(&config)
	if err != nil {
		return SignaturesConfig{}, fmt.Errorf("failed decoding CEL signature config YAML: %w", err)
	}

	if config.Kind != KindSignaturesConfig {
		return SignaturesConfig{}, fmt.Errorf("unrecognized config kind: expected %s got %s", KindSignaturesConfig, config.Kind)
	}
	if config.APIVersion != APIVersionV1Alpha1 {
		return SignaturesConfig{}, fmt.Errorf("unrecognized config apiVersion: expected %s got %s", APIVersionV1Alpha1, config.APIVersion)
	}
	return config, nil
}

// NewConfigsFromDir loads CEL SignatureConfig objects from the specified
// directory.
func NewConfigsFromDir(dirPath string) ([]SignaturesConfig, error) {
	configFiles, err := walkFilesWithExtensions(dirPath, extensions)
	if err != nil {
		return nil, fmt.Errorf("failed walking dir %s: %w", dirPath, err)
	}
	var configs []SignaturesConfig
	for _, configFile := range configFiles {
		config, err := NewConfigFromFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("failed loading config from file: %s: %w", configFile, err)
		}
		configs = append(configs, config)
	}
	return configs, nil
}

// walkFilesWithExtensions walks the file tree rooted at rootDir and returns
// paths of files with the specified extensions.
func walkFilesWithExtensions(rootDir string, extensions []string) ([]string, error) {
	var files []string

	err := capabilities.GetInstance().Requested(
		func() error {
			err := filepath.WalkDir(rootDir,
				func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}

					if d.IsDir() {
						return nil
					}

					for _, s := range extensions {
						if strings.HasSuffix(strings.ToLower(path), "."+s) {
							files = append(files, path)
							return nil
						}
					}

					return nil
				})
			return err
		},
		cap.DAC_OVERRIDE,
	)

	return files, err

}
