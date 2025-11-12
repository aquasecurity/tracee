package flags

import (
	"strings"

	"github.com/aquasecurity/tracee/common/errfmt"
)

const (
	SearchPathsFlag = "search-paths"

	signaturesInvalidFlagFormat = "invalid signatures flag: %s, use 'trace man signatures' for more info"
)

type SignaturesConfig struct {
	SearchPaths []string
}

// PrepareSignatures prepares the signatures configuration from the command line flags
// --signatures search-paths=/path1,/path2
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
		case SearchPathsFlag:
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
