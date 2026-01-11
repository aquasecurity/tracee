package flags

import (
	"github.com/spf13/viper"

	"github.com/aquasecurity/tracee/common/errfmt"
)

type cliFlagger interface {
	flags() []string
}

// GetFlagsFromViper returns a slice of flags from a given config key.
// It relies on the fact that the config key is a viper.Gettable and that the
// config value complies with the cliFlagger interface (when structured).
func GetFlagsFromViper(key string) ([]string, error) {
	var flagger cliFlagger
	rawValue := viper.Get(key)

	switch key {
	case ServerFlag:
		flagger = &ServerConfig{}
	case CapabilitiesFlag:
		flagger = &CapabilitiesConfig{}
	case DetectorsFlag:
		flagger = &DetectorsConfig{}
	case LoggingFlag:
		flagger = &LogConfig{}
	case OutputFlag:
		flagger = &OutputConfig{}
	case StoresFlag:
		flagger = &StoresConfig{}
	case BuffersFlag:
		flagger = &BuffersConfig{}
	case EnrichmentFlag:
		flagger = &EnrichmentConfig{}
	case ArtifactsFlag:
		flagger = &ArtifactsConfig{}
	default:
		return nil, errfmt.Errorf("unrecognized key: %s", key)
	}

	return getConfigFlags(rawValue, flagger, key)
}

// getConfigFlags handles the given config key via viper.UnmarshalKey for both
// structured and raw cli flags.
func getConfigFlags(rawValue interface{}, flagger cliFlagger, key string) ([]string, error) {
	switch v := rawValue.(type) {
	// structured flags
	case map[string]interface{}:
		err := viper.UnmarshalKey(key, flagger)
		if err != nil {
			return nil, errfmt.WrapError(err)
		}
		return flagger.flags(), nil

	// raw cli flags
	case []interface{}, []string:
		flags := make([]string, 0)
		err := viper.UnmarshalKey(key, &flags)
		if err != nil {
			return nil, errfmt.WrapError(err)
		}
		return flags, nil

	default:
		return nil, errfmt.Errorf("unrecognized type %T for key %s", v, key)
	}
}
