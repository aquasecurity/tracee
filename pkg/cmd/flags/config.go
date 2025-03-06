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
	case "containers":
		flagger = &ContainerConfig{}
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

type ContainerConfig struct {
	Enrich   *bool          `mapstructure:"enrich"`
	Sockets  []SocketConfig `mapstructure:"sockets"`
	Cgroupfs CgroupfsConfig `mapstructure:"cgroupfs"`
}

type CgroupfsConfig struct {
	Path  string `mapstructure:"path"`
	Force bool   `mapstructure:"force"`
}

type SocketConfig struct {
	Runtime string `mapstructure:"runtime"`
	Socket  string `mapstructure:"socket"`
}

func (c *ContainerConfig) flags() []string {
	flags := make([]string, 0)

	if c.Enrich == nil {
		// default to true
		flags = append(flags, "enrich=true")
	} else if *c.Enrich {
		// if set to true
		flags = append(flags, "enrich=true")
	} else {
		// if set to false
		flags = append(flags, "enrich=false")
	}

	if c.Cgroupfs.Path != "" {
		flags = append(flags, fmt.Sprintf("cgroupfs.path=%s", c.Cgroupfs.Path))
	}
	if c.Cgroupfs.Force {
		flags = append(flags, "cgroupfs.force=true")
	}

	for _, socket := range c.Sockets {
		flags = append(flags, socket.flags()...)
	}

	return flags
}

func (c *SocketConfig) flags() []string {
	flags := make([]string, 0)

	if c.Runtime != "" && c.Socket != "" {
		flags = append(flags, fmt.Sprintf("sockets.%s=%s", c.Runtime, c.Socket))
	}

	return flags
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

type OutputConfig struct {
	Options      OutputOptsConfig               `mapstructure:"options"`
	Table        OutputFormatConfig             `mapstructure:"table"`
	TableVerbose OutputFormatConfig             `mapstructure:"table-verbose"`
	JSON         OutputFormatConfig             `mapstructure:"json"`
	GoTemplate   OutputGoTemplateConfig         `mapstructure:"gotemplate"`
	Forwards     map[string]OutputForwardConfig `mapstructure:"forward"`
	Webhooks     map[string]OutputWebhookConfig `mapstructure:"webhook"`
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

	// formats with files
	formatFilesMap := map[string][]string{
		"table":         c.Table.Files,
		"table-verbose": c.TableVerbose.Files,
		"json":          c.JSON.Files,
	}
	for format, files := range formatFilesMap {
		for _, file := range files {
			flags = append(flags, fmt.Sprintf("%s:%s", format, file))
		}
	}

	// gotemplate
	if c.GoTemplate.Template != "" {
		templateFlag := fmt.Sprintf("gotemplate=%s", c.GoTemplate.Template)
		if len(c.GoTemplate.Files) > 0 {
			templateFlag += ":" + strings.Join(c.GoTemplate.Files, ",")
		}

		flags = append(flags, templateFlag)
	}

	// forward
	for forwardName, forward := range c.Forwards {
		_ = forwardName
		url := fmt.Sprintf("%s://", forward.Protocol)

		if forward.User != "" && forward.Password != "" {
			url += fmt.Sprintf("%s:%s@", forward.User, forward.Password)
		}

		url += fmt.Sprintf("%s:%d", forward.Host, forward.Port)

		if forward.Tag != "" {
			url += fmt.Sprintf("?tag=%s", forward.Tag)
		}

		flags = append(flags, fmt.Sprintf("forward:%s", url))
	}

	// webhook
	for webhookName, webhook := range c.Webhooks {
		_ = webhookName
		delim := "?"
		url := fmt.Sprintf("%s://%s:%d", webhook.Protocol, webhook.Host, webhook.Port)
		if webhook.Timeout != "" {
			url += fmt.Sprintf("%stimeout=%s", delim, webhook.Timeout)
			delim = "&"
		}
		if webhook.GoTemplate != "" {
			url += fmt.Sprintf("%sgotemplate=%s", delim, webhook.GoTemplate)
			delim = "&"
		}
		if webhook.ContentType != "" {
			url += fmt.Sprintf("%scontentType=%s", delim, webhook.ContentType)
		}

		flags = append(flags, fmt.Sprintf("webhook:%s", url))
	}

	return flags
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

type OutputFormatConfig struct {
	Files []string `mapstructure:"files"`
}

type OutputGoTemplateConfig struct {
	Template string   `mapstructure:"template"`
	Files    []string `mapstructure:"files"`
}

type OutputForwardConfig struct {
	Protocol string `mapstructure:"protocol"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Tag      string `mapstructure:"tag"`
}

type OutputWebhookConfig struct {
	Protocol    string `mapstructure:"protocol"`
	Host        string `mapstructure:"host"`
	Port        int    `mapstructure:"port"`
	Timeout     string `mapstructure:"timeout"`
	GoTemplate  string `mapstructure:"gotemplate"`
	ContentType string `mapstructure:"content-type"`
}
