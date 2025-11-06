package cobra

import (
	"fmt"
	"os"

	"github.com/spf13/viper"

	"github.com/aquasecurity/tracee/common/errfmt"
	outputflags "github.com/aquasecurity/tracee/pkg/cmd/flags"
	serverflag "github.com/aquasecurity/tracee/pkg/cmd/flags/server"
	"github.com/aquasecurity/tracee/pkg/config"
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
	case serverflag.ServerFlag:
		flagger = &ServerConfig{}
	case "proctree":
		flagger = &ProcTreeConfig{}
	case "capabilities":
		flagger = &CapabilitiesConfig{}
	case "containers":
		flagger = &ContainerConfig{}
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

type ContainerConfig struct {
	Enrich   *bool          `mapstructure:"enrich"`
	Sockets  []SocketConfig `mapstructure:"sockets"`
	Cgroupfs CgroupfsConfig `mapstructure:"cgroupfs"`
}

type CgroupfsConfig struct {
	Path  string `mapstructure:"path"`
	Force bool   `mapstructure:"force"`
}

//
// server flag
//

type ServerConfig struct {
	HttpAddress string `mapstructure:"http-address"`
	GrpcAddress string `mapstructure:"grpc-address"`
	Metrics     bool   `mapstructure:"metrics"`
	Pprof       bool   `mapstructure:"pprof"`
	Healthz     bool   `mapstructure:"healthz"`
	Pyroscope   bool   `mapstructure:"pyroscope"`
}

func (s *ServerConfig) flags() []string {
	flags := make([]string, 0)

	if s.GrpcAddress != "" {
		flags = append(flags, fmt.Sprintf("%s=%s", serverflag.GRPCAddressFlag, s.GrpcAddress))
	}
	if s.HttpAddress != "" {
		flags = append(flags, fmt.Sprintf("%s=%s", serverflag.HTTPAddressFlag, s.HttpAddress))
	}
	if s.Metrics {
		flags = append(flags, serverflag.MetricsEndpointFlag)
	}
	if s.Pprof {
		flags = append(flags, serverflag.PProfEndpointFlag)
	}
	if s.Healthz {
		flags = append(flags, serverflag.HealthzEndpointFlag)
	}
	if s.Pyroscope {
		flags = append(flags, serverflag.PyroscopeAgentEndpointFlag)
	}
	return flags
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

func isStructured(key string) bool {
	rawValue := viper.Get(key)
	_, ok := rawValue.(map[string]interface{})

	return ok
}

func getStructuredOutputConfig() (*OutputConfig, error) {
	var output OutputConfig
	err := viper.UnmarshalKey("output", &output)
	if err != nil {
		return nil, err
	}

	// validation
	for _, stream := range output.Streams {
		if stream.Name == "" {
			return nil, errfmt.Errorf("validaiton error: name is mandatory for streams")
		}
	}

	for dIdx := range output.Destinations {
		destination := &output.Destinations[dIdx]
		if destination.Name == "" {
			return nil, errfmt.Errorf("validaiton error: name is mandatory for destinations")
		}

		if destination.Type == "" {
			destination.Type = "file"
		}

		if destination.Type == "file" && destination.Format == "" {
			destination.Format = "table"
		}

		if (destination.Type == "webhook" || destination.Type == "forward") &&
			destination.Url == "" {
			return nil, errfmt.Errorf("validaiton error: url is mandatory in destination for %s", destination.Type)
		}
	}

	return &output, nil
}

// The following structures are very similar to the ones defined in pkg/config/config.go.
// The duplication allows the separation between the configuration passed by the user and
// the configuration used to run tracee
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

type OutputConfig struct {
	Options      OutputOptsConfig     `mapstructure:"options"`
	Destinations []DestinationsConfig `mapstructure:"destinations"`
	Streams      []StreamConfig       `mapstructure:"streams"`
}

// For the output we are using a different path when the configuration is coming
// from a structured configuration file.
func (OutputConfig) flags() []string {
	return []string{}
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

func prepareTraceeConfig(c OutputConfig, containerMode config.ContainerMode) (*config.OutputConfig, error) {
	cfg := &config.OutputConfig{}
	declaredDestinations := map[string]int{}

	for _, destination := range c.Destinations {
		declaredDestinations[destination.Name] = 0
	}

	// check that all destinations used in the streams exist in the destinations section
	// and that each destination is used exactly once
	for _, stream := range c.Streams {
		for _, destinationInStream := range stream.Destinations {
			if _, ok := declaredDestinations[destinationInStream]; !ok {
				return nil, fmt.Errorf("destination %s used in stream %s doesn't exist among the destinations",
					destinationInStream, stream.Name)
			}

			declaredDestinations[destinationInStream]++
			if count := declaredDestinations[destinationInStream]; count > 1 {
				return nil, fmt.Errorf("destination %s used multiple times, which is not allowed", destinationInStream)
			}
		}
	}

	traceeConfigDestinations, err := prepareTraceeDestinationConfigs(c.Destinations, containerMode)
	if err != nil {
		return nil, err
	}

	// create streams from the config file
	for _, s := range c.Streams {
		streamsDestinations := []config.Destination{}
		for _, destinationInStream := range s.Destinations {
			d := traceeConfigDestinations[destinationInStream]
			streamsDestinations = append(streamsDestinations, d)
		}

		cfg.Streams = append(cfg.Streams, config.Stream{
			Name:         s.Name,
			Destinations: streamsDestinations,
			Filters: config.StreamFilters{
				Policies: s.Filters.Policies,
				Events:   s.Filters.Events,
			},
			Buffer: config.StreamBuffer{
				Size: s.Buffer.Size,
				Mode: config.StreamBufferMode(s.Buffer.Mode),
			},
		})
	}

	// create streams for the destinations that are not used in streams
	syntheticStreams := []config.Stream{}
	for _, destination := range c.Destinations {
		if d := declaredDestinations[destination.Name]; d > 0 {
			continue
		}

		syntheticStreams = append(syntheticStreams, config.Stream{
			Name:         destination.Name + "-stream",
			Destinations: []config.Destination{traceeConfigDestinations[destination.Name]},
		})
	}
	cfg.Streams = append(cfg.Streams, syntheticStreams...)

	// Create default stream if no streams are defined by the user
	// and option.none == false
	if len(cfg.Streams) == 0 && !c.Options.None {
		cfg.Streams = append(cfg.Streams, config.Stream{
			Name: "default-stream",
			Destinations: []config.Destination{
				{
					Name:          "default-destination",
					Type:          "file",
					Format:        "table",
					Path:          "stdout",
					File:          os.Stdout,
					ContainerMode: containerMode,
				},
			},
		})
	}

	// Set options
	err = setOptions(c.Options, cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

// prepareTraceeDestinationConfigs converts DestinationConfig to config.Destination and create the needed resources
func prepareTraceeDestinationConfigs(destinations []DestinationsConfig, containerMode config.ContainerMode) (map[string]config.Destination, error) {
	traceeConfigDestinations := map[string]config.Destination{}
	for _, dst := range destinations {
		outputDestination := config.Destination{
			Name:          dst.Name,
			Type:          dst.Type,
			Format:        dst.Format,
			Path:          dst.Path,
			Url:           dst.Url,
			ContainerMode: containerMode,
		}

		if dst.Type == "file" {
			outputDestination.File = os.Stdout

			if dst.Path != "stdout" && dst.Path != "" {
				outputFile, err := outputflags.CreateOutputFile(dst.Path)
				if err != nil {
					return nil, err
				}

				outputDestination.File = outputFile
			}
		}

		traceeConfigDestinations[outputDestination.Name] = outputDestination
	}

	return traceeConfigDestinations, nil
}

// setOptions sets the needed options from the user config to the tracee config
func setOptions(options OutputOptsConfig, traceeConfig *config.OutputConfig) error {
	if options.StackAddresses {
		if err := outputflags.SetOption(traceeConfig, "stack-addresses"); err != nil {
			return err
		}
	}

	if options.ExecEnv {
		if err := outputflags.SetOption(traceeConfig, "exec-env"); err != nil {
			return err
		}
	}

	if options.ExecHash != "" {
		if err := outputflags.SetOption(traceeConfig, fmt.Sprintf("exec-hash=%s", options.ExecHash)); err != nil {
			return err
		}
	}

	if options.ParseArguments {
		if err := outputflags.SetOption(traceeConfig, "parse-arguments"); err != nil {
			return err
		}
	}

	if options.ParseArgumentsFDs {
		if err := outputflags.SetOption(traceeConfig, "parse-arguments-fds"); err != nil {
			return err
		}
	}

	if options.SortEvents {
		if err := outputflags.SetOption(traceeConfig, "sort-events"); err != nil {
			return err
		}
	}

	return nil
}
