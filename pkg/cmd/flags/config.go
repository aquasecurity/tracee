package flags

import (
	"fmt"
	"strings"

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
	case "capabilities":
		flagger = &CapabilitiesConfig{}
	case LoggingFlag:
		flagger = &LogConfig{}
	case "output":
		flagger = &OutputConfig{}
	case RuntimeFlag:
		flagger = &RuntimeConfig{}
	case StoresFlag:
		flagger = &StoresConfig{}
	case BuffersFlag:
		flagger = &BuffersConfig{}
	case EnrichmentFlag:
		flagger = &EnrichmentConfig{}
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

//
// capabilities flag
//

type CapabilitiesConfig struct {
	Bypass bool     `mapstructure:"bypass"`
	Add    []string `mapstructure:"add"`
	Drop   []string `mapstructure:"drop"`
}

func (c *CapabilitiesConfig) flags() []string {
	flags := make([]string, 0)

	flags = append(flags, fmt.Sprintf("bypass=%v", c.Bypass))
	for _, cap := range c.Add {
		flags = append(flags, fmt.Sprintf("add=%s", cap))
	}
	for _, cap := range c.Drop {
		flags = append(flags, fmt.Sprintf("drop=%s", cap))
	}

	return flags
}

//
// output flag
//

type StreamBufferMode string

const (
	StreamBufferBlock StreamBufferMode = "block"
	StreamBufferDrop  StreamBufferMode = "drop"
)

type StreamFiltersConfig struct {
	Policies []string `mapstructure:"policies"`
	Events   []string `mapstructure:"events"`
}

type StreamBufferConfig struct {
	Size int              `mapstructure:"size"`
	Mode StreamBufferMode `mapstructure:"mode"`
}

type StreamConfig struct {
	Name         string              `mapstructure:"name"`
	Destinations []string            `mapstructure:"destinations"`
	Filters      StreamFiltersConfig `mapstructure:"filters"`
	Buffer       StreamBufferConfig  `mapstructure:"buffer"`
}

type DestinationsConfig struct {
	Name   string `mapstructure:"name"`
	Type   string `mapstructure:"type"`
	Format string `mapstructure:"format"`
	Path   string `mapstructure:"path"`
	Url    string `mapstructure:"url"`
}

type OutputOptsConfig struct {
	None              bool   `mapstructure:"none"`
	StackAddresses    bool   `mapstructure:"stack-addresses"`
	ExecEnv           bool   `mapstructure:"exec-env"`
	ExecHash          string `mapstructure:"exec-hash"`
	ParseArguments    bool   `mapstructure:"parse-arguments"`
	ParseArgumentsFDs bool   `mapstructure:"parse-arguments-fds"`
	SortEvents        bool   `mapstructure:"sort-events"`
}

type OutputConfig struct {
	Options      OutputOptsConfig     `mapstructure:"options"`
	Destinations []DestinationsConfig `mapstructure:"destinations"`
	Streams      []StreamConfig       `mapstructure:"streams"`
}

func (c *OutputConfig) flags() []string {
	flags := []string{}

	// options flags
	if c.Options.None {
		flags = append(flags, "none")
	}
	if c.Options.StackAddresses {
		flags = append(flags, "option:stack-addresses")
	}
	if c.Options.ExecEnv {
		flags = append(flags, "option:exec-env")
	}
	if c.Options.ExecHash != "" {
		flags = append(flags, fmt.Sprintf("option:exec-hash=%s", c.Options.ExecHash))
	}
	if c.Options.ParseArguments {
		flags = append(flags, "option:parse-arguments")
	}
	if c.Options.ParseArgumentsFDs {
		flags = append(flags, "option:parse-arguments-fds")
	}
	if c.Options.SortEvents {
		flags = append(flags, "option:sort-events")
	}

	// destinations
	for _, destination := range c.Destinations {
		if destination.Format != "" {
			flags = append(flags, fmt.Sprintf("destinations.%s.format=%s", destination.Name, destination.Format))
		}

		if destination.Type != "" {
			flags = append(flags, fmt.Sprintf("destinations.%s.type=%s", destination.Name, destination.Type))
		}

		if destination.Path != "" {
			flags = append(flags, fmt.Sprintf("destinations.%s.path=%s", destination.Name, destination.Path))
		}

		if destination.Url != "" {
			flags = append(flags, fmt.Sprintf("destinations.%s.url=%s", destination.Name, destination.Url))
		}
	}

	// streams
	for _, stream := range c.Streams {
		if stream.Buffer.Mode != "" {
			flags = append(flags, fmt.Sprintf("streams.%s.buffer.mode=%s", stream.Name, stream.Buffer.Mode))
		}

		if stream.Buffer.Size >= 0 {
			flags = append(flags, fmt.Sprintf("streams.%s.buffer.size=%d", stream.Name, stream.Buffer.Size))
		}

		if len(stream.Destinations) > 0 {
			flags = append(flags, fmt.Sprintf("streams.%s.destinations=%s", stream.Name, strings.Join(stream.Destinations, ",")))
		}

		if len(stream.Filters.Events) > 0 {
			flags = append(flags, fmt.Sprintf("streams.%s.filters.events=%s", stream.Name, strings.Join(stream.Filters.Events, ",")))
		}

		if len(stream.Filters.Policies) > 0 {
			flags = append(flags, fmt.Sprintf("streams.%s.filters.policies=%s", stream.Name, strings.Join(stream.Filters.Policies, ",")))
		}
	}

	return flags
}
