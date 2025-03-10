package cobra

import (
	"fmt"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"

	"github.com/aquasecurity/tracee/pkg/errfmt"
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
	case "server":
		flagger = &ServerConfig{}
	case "cache":
		flagger = &CacheConfig{}
	case "proctree":
		flagger = &ProcTreeConfig{}
	case "capabilities":
		flagger = &CapabilitiesConfig{}
	case "cri":
		switch v := rawValue.(type) {
		case []string: // via cli
			return getConfigFlags(rawValue, nil, "cri")
		case []interface{}: // via config file
			return getCRIConfigFlags(rawValue)
		default:
			return nil, errfmt.Errorf("unrecognized type %T for cri", v)
		}
	case "log":
		flagger = &LogConfig{}
	case "output":
		flagger = &OutputConfig{}
	case "dnscache":
		flagger = &DnsCacheConfig{}
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

// getCRIConfigFlags handles the cri config key, which is a special case.
// For structured flags, it uses mapstructure to decode the config into a
// CRIConfig struct. For raw cli flags, it returns the raw values as strings.
func getCRIConfigFlags(rawValue interface{}) ([]string, error) {
	rawValues, ok := rawValue.([]interface{})
	if !ok {
		return nil, errfmt.Errorf("unrecognized type %T for cri", rawValue)
	}

	flags := make([]string, 0)
	flagger := &CRIConfig{}
	for _, raw := range rawValues {
		switch v := raw.(type) {
		// raw cli flags
		case string:
			// cri:
			//     - containerd:/var/run/containerd/containerd.sock
			//     - docker:/var/run/docker.sock
			flags = append(flags, v)

		// structured flags
		case map[string]interface{}:
			// cri:
			//     - runtime:
			//         name: containerd
			//         socket: /var/run/containerd/containerd.sock
			//     - runtime:
			//         name: docker
			//         socket: /var/run/docker.sock
			runtimeMap, exists := v["runtime"].(map[string]interface{})
			if !exists {
				return nil, errfmt.Errorf("runtime key not found or not a map")
			}
			if err := mapstructure.Decode(runtimeMap, flagger); err != nil {
				return nil, errfmt.WrapError(err)
			}
			flags = append(flags, flagger.flags()...)

		default:
			return nil, errfmt.Errorf("unrecognized type %T for cri", v)
		}
	}

	return flags, nil
}

//
// server flag
//

type ServerConfig struct {
	Http HttpConfig `mapstructure:"http"`
	Grpc GrpcConfig `mapstructure:"grpc"`
}
type HttpConfig struct {
	Metrics   bool   `mapstructure:"metrics"`
	Pprof     bool   `mapstructure:"pprof"`
	Healthz   bool   `mapstructure:"healthz"`
	Pyroscope bool   `mapstructure:"pyroscope"`
	Address   string `mapstructure:"address"`
}

type GrpcConfig struct {
	Address string `mapstructure:"address"`
}

func (s *ServerConfig) flags() []string {
	flags := make([]string, 0)

	if s.Grpc.Address != "" {
		flags = append(flags, fmt.Sprintf("grpc.address=%s", s.Grpc.Address))
	}
	if s.Http.Address != "" {
		flags = append(flags, fmt.Sprintf("http.address=%s", s.Http.Address))
	}
	if s.Http.Metrics {
		flags = append(flags, "http.metrics=true")
	}
	if s.Http.Pprof {
		flags = append(flags, "http.pprof=true")
	}
	if s.Http.Healthz {
		flags = append(flags, "http.healthz=true")
	}
	if s.Http.Pyroscope {
		flags = append(flags, "http.pyroscope=true")
	}
	return flags
}

//
// config flag
//

type CacheConfig struct {
	Type string `mapstructure:"type"`
	Size int    `mapstructure:"size"`
}

func (c *CacheConfig) flags() []string {
	flags := make([]string, 0)

	if c.Type != "" {
		flags = append(flags, fmt.Sprintf("cache-type=%s", c.Type))
	}
	if c.Size != 0 {
		flags = append(flags, fmt.Sprintf("mem-cache-size=%d", c.Size))
	}

	return flags
}

//
// proctree flag
//

type ProcTreeConfig struct {
	Source string              `mapstructure:"source"`
	Cache  ProcTreeCacheConfig `mapstructure:"cache"`
}

type ProcTreeCacheConfig struct {
	Process int `mapstructure:"process"`
	Thread  int `mapstructure:"thread"`
}

func (c *ProcTreeConfig) flags() []string {
	flags := make([]string, 0)

	if c.Source != "" {
		if c.Source == "none" {
			flags = append(flags, "none")
		} else {
			flags = append(flags, fmt.Sprintf("source=%s", c.Source))
		}
	}
	if c.Cache.Process != 0 {
		flags = append(flags, fmt.Sprintf("process-cache=%d", c.Cache.Process))
	}
	if c.Cache.Thread != 0 {
		flags = append(flags, fmt.Sprintf("thread-cache=%d", c.Cache.Thread))
	}

	return flags
}

//
// dnscache flag
//

type DnsCacheConfig struct {
	Enable bool `mapstructure:"enable"`
	Size   int  `mapstructure:"size"`
}

func (c *DnsCacheConfig) flags() []string {
	flags := make([]string, 0)

	if !c.Enable {
		flags = append(flags, "none")
		return flags
	}

	if c.Size != 0 {
		flags = append(flags, fmt.Sprintf("size=%d", c.Size))
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
// cri flag
//

type CRIConfig struct {
	Name   string `mapstructure:"name"`
	Socket string `mapstructure:"socket"`
}

func (c *CRIConfig) flags() []string {
	flags := make([]string, 0)

	if c.Name != "" && c.Socket != "" {
		flags = append(flags, fmt.Sprintf("%s:%s", c.Name, c.Socket))
	}

	return flags
}

//
// log flag
//

type LogConfig struct {
	Level     string             `mapstructure:"level"`
	File      string             `mapstructure:"file"`
	Aggregate LogAggregateConfig `mapstructure:"aggregate"`
	Filters   LogFilterConfig    `mapstructure:"filters"`
}

func (c *LogConfig) flags() []string {
	flags := []string{}

	// level
	if c.Level != "" {
		flags = append(flags, c.Level)
	}

	// file
	if c.File != "" {
		flags = append(flags, fmt.Sprintf("file:%s", c.File))
	}

	// aggregate
	if c.Aggregate.Enabled {
		if c.Aggregate.FlushInterval == "" {
			flags = append(flags, "aggregate")
		} else {
			flags = append(flags, fmt.Sprintf("aggregate:%s", c.Aggregate.FlushInterval))
		}
	}

	// filters
	if c.Filters.LibBPF {
		flags = append(flags, "filter:libbpf")
	}

	flags = append(flags, getLogFilterAttrFlags(false, c.Filters.In)...)
	flags = append(flags, getLogFilterAttrFlags(true, c.Filters.Out)...)

	return flags
}

type LogAggregateConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	FlushInterval string `mapstructure:"flush-interval"`
}

type LogFilterConfig struct {
	LibBPF bool                `mapstructure:"libbpf"`
	In     LogFilterAttributes `mapstructure:"in"`
	Out    LogFilterAttributes `mapstructure:"out"`
}

type LogFilterAttributes struct {
	Msg   []string `mapstructure:"msg"`
	Pkg   []string `mapstructure:"pkg"`
	File  []string `mapstructure:"file"`
	Level []string `mapstructure:"lvl"`
	Regex []string `mapstructure:"regex"`
}

func getLogFilterAttrFlags(filterOut bool, attrs LogFilterAttributes) []string {
	attrFlags := []string{}
	suffix := ""

	if filterOut {
		suffix = "-out"
	}

	// msg
	for _, msg := range attrs.Msg {
		attrFlags = append(attrFlags, fmt.Sprintf("filter%s:msg=%s", suffix, msg))
	}

	// pkg
	for _, pkg := range attrs.Pkg {
		attrFlags = append(attrFlags, fmt.Sprintf("filter%s:pkg=%s", suffix, pkg))
	}

	// file
	for _, file := range attrs.File {
		attrFlags = append(attrFlags, fmt.Sprintf("filter%s:file=%s", suffix, file))
	}

	// level
	for _, level := range attrs.Level {
		attrFlags = append(attrFlags, fmt.Sprintf("filter%s:lvl=%s", suffix, level))
	}

	// regex
	for _, regex := range attrs.Regex {
		attrFlags = append(attrFlags, fmt.Sprintf("filter%s:regex=%s", suffix, regex))
	}

	return attrFlags
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
