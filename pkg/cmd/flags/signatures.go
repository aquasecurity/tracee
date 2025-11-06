package flags

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/common/errfmt"
)

const (
	SignaturesFlag = "signatures"

	searchPathsFlag             = "search-paths"
	signaturesInvalidFlagFormat = "invalid signatures flag: %s, use 'trace man signatures' for more info"
)

// SignaturesConfig represents the configuration for signatures.
type SignaturesConfig struct {
	SearchPaths []string `mapstructure:"search-paths"`
}

// flags returns the flags for the signatures configuration.
func (c *SignaturesConfig) flags() []string {
	flags := make([]string, 0)

	if len(c.SearchPaths) > 0 {
		flags = append(flags, fmt.Sprintf("search-paths=%s", strings.Join(c.SearchPaths, ",")))
	}

	return flags
}

// PrepareSignatures prepares the signatures configuration from the command line flags
func PrepareSignatures(signatures []string) (SignaturesConfig, error) {
	config := SignaturesConfig{
		SearchPaths: []string{},
	}

	for _, flag := range signatures {
		parts := strings.SplitN(flag, "=", 2)
		if len(parts) != 2 {
			return SignaturesConfig{}, errfmt.Errorf(signaturesInvalidFlagFormat, flag)
		}

		flagName := parts[0]
		flagValue := parts[1]

		switch flagName {
		case searchPathsFlag:
			if flagValue == "" {
				return SignaturesConfig{}, errfmt.Errorf("invalid signatures flag: %s value can't be empty, use 'trace man signatures' for more info", flagName)
			}
			paths := strings.Split(flagValue, ",")
			for _, path := range paths {
				trimmedPath := strings.TrimSpace(path)
				if trimmedPath != "" {
					config.SearchPaths = append(config.SearchPaths, trimmedPath)
				}
			}
		default:
			return SignaturesConfig{}, errfmt.Errorf(signaturesInvalidFlagFormat, flag)
		}
	}

	return config, nil
}
