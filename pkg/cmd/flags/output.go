package flags

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/common/digest"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/pkg/config"
)

const (
	OutputFlag = "output"

	// output option flags
	noneFlag              = "none"
	optionFlag            = "option"
	stackAddressesFlag    = "stack-addresses"
	execEnvFlag           = "exec-env"
	parseArgumentsFlag    = "parse-arguments"
	parseArgumentsFDsFlag = "parse-arguments-fds"
	sortEventsFlag        = "sort-events"

	// output format flags
	tableFlag        = "table"
	jsonFlag         = "json"
	forwardFlag      = "forward"
	webhookFlag      = "webhook"
	gotemplatePrefix = "gotemplate="

	// destination flags
	destinationsPrefix = "destinations."

	// stream flags
	streamsPrefix = "streams."
)

// StreamBufferMode is the mode of the stream buffer.
type StreamBufferMode string

// StreamBufferModeBlock is the block mode of the stream buffer.
const (
	// StreamBufferModeBlock is the block mode of the stream buffer.
	StreamBufferBlock StreamBufferMode = "block"
	// StreamBufferModeDrop is the drop mode of the stream buffer.
	StreamBufferDrop StreamBufferMode = "drop"
)

// StreamFiltersConfig is the filters of the stream.
type StreamFiltersConfig struct {
	Policies []string `mapstructure:"policies"`
	Events   []string `mapstructure:"events"`
}

// StreamBufferConfig is the buffer of the stream.
type StreamBufferConfig struct {
	Size int              `mapstructure:"size"`
	Mode StreamBufferMode `mapstructure:"mode"`
}

// StreamConfig is the config of the stream.
type StreamConfig struct {
	Name         string              `mapstructure:"name"`
	Destinations []string            `mapstructure:"destinations"`
	Filters      StreamFiltersConfig `mapstructure:"filters"`
	Buffer       StreamBufferConfig  `mapstructure:"buffer"`
}

// DestinationsConfig is the config of the destinations.
type DestinationsConfig struct {
	Name   string `mapstructure:"name"`
	Type   string `mapstructure:"type"`
	Format string `mapstructure:"format"`
	Path   string `mapstructure:"path"`
	Url    string `mapstructure:"url"`
}

// OutputOptsConfig is the options of the output.
type OutputOptsConfig struct {
	None              bool   `mapstructure:"none"`
	StackAddresses    bool   `mapstructure:"stack-addresses"`
	ExecEnv           bool   `mapstructure:"exec-env"`
	ExecHash          string `mapstructure:"exec-hash"`
	ParseArguments    bool   `mapstructure:"parse-arguments"`
	ParseArgumentsFDs bool   `mapstructure:"parse-arguments-fds"`
	SortEvents        bool   `mapstructure:"sort-events"`
}

// OutputConfig is the config of the output.
type OutputConfig struct {
	Options      OutputOptsConfig     `mapstructure:"options"`
	Destinations []DestinationsConfig `mapstructure:"destinations"`
	Streams      []StreamConfig       `mapstructure:"streams"`
}

// flags returns the flags of the output.
func (c *OutputConfig) flags() []string {
	flags := []string{}

	// options flags
	if c.Options.None {
		flags = append(flags, noneFlag)
	}
	if c.Options.StackAddresses {
		flags = append(flags, fmt.Sprintf("%s:%s", optionFlag, stackAddressesFlag))
	}
	if c.Options.ExecEnv {
		flags = append(flags, fmt.Sprintf("%s:%s", optionFlag, execEnvFlag))
	}
	if c.Options.ExecHash != "" {
		flags = append(flags, fmt.Sprintf("%s:exec-hash=%s", optionFlag, c.Options.ExecHash))
	}
	if c.Options.ParseArguments {
		flags = append(flags, fmt.Sprintf("%s:%s", optionFlag, parseArgumentsFlag))
	}
	if c.Options.ParseArgumentsFDs {
		flags = append(flags, fmt.Sprintf("%s:%s", optionFlag, parseArgumentsFDsFlag))
	}
	if c.Options.SortEvents {
		flags = append(flags, fmt.Sprintf("%s:%s", optionFlag, sortEventsFlag))
	}

	// destinations
	for _, destination := range c.Destinations {
		if destination.Format != "" {
			flags = append(flags, fmt.Sprintf("%s%s.format=%s", destinationsPrefix, destination.Name, destination.Format))
		}

		if destination.Type != "" {
			flags = append(flags, fmt.Sprintf("%s%s.type=%s", destinationsPrefix, destination.Name, destination.Type))
		}

		if destination.Path != "" {
			flags = append(flags, fmt.Sprintf("%s%s.path=%s", destinationsPrefix, destination.Name, destination.Path))
		}

		if destination.Url != "" {
			flags = append(flags, fmt.Sprintf("%s%s.url=%s", destinationsPrefix, destination.Name, destination.Url))
		}
	}

	// streams
	for _, stream := range c.Streams {
		if stream.Buffer.Mode != "" {
			flags = append(flags, fmt.Sprintf("%s%s.buffer.mode=%s", streamsPrefix, stream.Name, stream.Buffer.Mode))
		}

		if stream.Buffer.Size > 0 {
			flags = append(flags, fmt.Sprintf("%s%s.buffer.size=%d", streamsPrefix, stream.Name, stream.Buffer.Size))
		}

		if len(stream.Destinations) > 0 {
			flags = append(flags, fmt.Sprintf("%s%s.destinations=%s", streamsPrefix, stream.Name, strings.Join(stream.Destinations, ",")))
		}

		if len(stream.Filters.Events) > 0 {
			flags = append(flags, fmt.Sprintf("%s%s.filters.events=%s", streamsPrefix, stream.Name, strings.Join(stream.Filters.Events, ",")))
		}

		if len(stream.Filters.Policies) > 0 {
			flags = append(flags, fmt.Sprintf("%s%s.filters.policies=%s", streamsPrefix, stream.Name, strings.Join(stream.Filters.Policies, ",")))
		}
	}

	return flags
}

// PrepareOutput prepares the output config from the given output slice.
func PrepareOutput(outputSlice []string, containerMode config.ContainerMode) (*config.OutputConfig, error) {
	// TODO: decide if we want to separate the configs (cobra and tracee internals), or join them
	traceeConfig := &config.OutputConfig{}

	// outpath:format
	destinationMap := make(map[string]string)
	streamsFlags := []string{}
	declaredDestinations := map[string]*config.Destination{}

	// This for loop handle the simple output cases. Backward compatible with --output flags
	for _, o := range outputSlice {
		if strings.HasPrefix(o, streamsPrefix) {
			// skip streams computation because we need to have all
			// the destinations ready before processing them

			streamsFlags = append(streamsFlags, o)
			continue
		}

		if strings.HasPrefix(o, destinationsPrefix) {
			err := parseDestinationFlag(o, declaredDestinations)
			if err != nil {
				return nil, err
			}

			continue
		}

		outputParts := strings.SplitN(o, ":", 2)

		if strings.HasPrefix(outputParts[0], gotemplatePrefix) {
			err := parseFormat(outputParts, destinationMap)
			if err != nil {
				return nil, err
			}
			continue
		}

		switch outputParts[0] {
		case noneFlag:
			if len(outputParts) > 1 {
				return nil, NoneOutputPathError()
			}
			destinationMap["stdout"] = "ignore"
		case tableFlag, jsonFlag:
			err := parseFormat(outputParts, destinationMap)
			if err != nil {
				return nil, err
			}
		case forwardFlag:
			err := validateURL(outputParts, forwardFlag)
			if err != nil {
				return nil, err
			}

			destinationMap[outputParts[1]] = forwardFlag
		case webhookFlag:
			err := validateURL(outputParts, webhookFlag)
			if err != nil {
				return nil, err
			}

			destinationMap[outputParts[1]] = webhookFlag
		case optionFlag:
			err := parseOption(outputParts, traceeConfig)
			if err != nil {
				return nil, err
			}
		default:
			return nil, InvalidOutputFlagError(outputParts[0])
		}
	}

	if err := validateOrDefaults(declaredDestinations); err != nil {
		return nil, err
	}

	declaredStreams := map[string]*config.Stream{}
	for _, flag := range streamsFlags {
		err := parseStreamFlag(flag, declaredStreams, declaredDestinations)
		if err != nil {
			return nil, err
		}
	}

	for _, stream := range declaredStreams {
		traceeConfig.Streams = append(traceeConfig.Streams, *stream)
	}

	// Create streams for destinations without one
	usedDestinations := map[string]struct{}{}
	for _, s := range declaredStreams {
		for _, streamDest := range s.Destinations {
			usedDestinations[streamDest.Name] = struct{}{}
		}
	}

	unusedDestinations := []config.Destination{}
	for _, dd := range declaredDestinations {
		_, ok := usedDestinations[dd.Name]
		if ok {
			continue
		}

		unusedDestinations = append(unusedDestinations, *dd)
	}

	if len(declaredDestinations) == 0 && len(destinationMap) == 0 {
		destinationMap["stdout"] = tableFlag
	}

	destinationConfigs, err := getDestinationConfigs(destinationMap, traceeConfig, containerMode)
	if err != nil {
		return nil, err
	}

	if len(destinationConfigs) > 0 || len(unusedDestinations) > 0 {
		traceeConfig.Streams = append(traceeConfig.Streams, config.Stream{
			Name:         "default-stream",
			Destinations: append(destinationConfigs, unusedDestinations...),
		})
	}

	return traceeConfig, nil
}

// parseDestinationFlag parses the given destination flag and sets it in the given existing map.
func parseDestinationFlag(flag string, existing map[string]*config.Destination) error {
	parts := strings.SplitN(flag, "=", 2)
	if len(parts) < 2 {
		return DestinationFlagIncorrectError(flag)
	}
	flagValue := parts[1]

	flagNameParts := strings.Split(parts[0], ".")

	if flagNameParts[0] != "destinations" {
		return WrongFunctionInvocationError("parseDestinationFlag()", flag)
	}

	if len(flagNameParts) != 3 {
		return DestinationFlagIncorrectError(flag)
	}

	destinationName := flagNameParts[1]
	if destinationName == "" {
		return DestinationFlagIncorrectError(flag)
	}

	if _, ok := existing[destinationName]; !ok {
		conf := config.Destination{
			Name: destinationName,
		}

		existing[destinationName] = &conf
	}

	destinationConfig := existing[destinationName]

	destinationField := flagNameParts[2]
	switch destinationField {
	case "type":
		destinationConfig.Type = flagValue
	case "format":
		destinationConfig.Format = flagValue
	case "path":
		destinationConfig.Path = flagValue
	case "url":
		destinationConfig.Url = flagValue
	default:
		return DestinationFlagIncorrectError(flag)
	}

	return nil
}

// validateOrDefaults validates the given destinations and sets the default values if needed.
func validateOrDefaults(destinations map[string]*config.Destination) error {
	for _, d := range destinations {
		if d.Type == "" {
			d.Type = "file"
		}

		if d.Type == "file" && d.Format == "" {
			d.Format = tableFlag
		}

		if d.Type == "file" && d.Path == "" {
			d.Path = "stdout"
		}

		if (d.Type == webhookFlag || d.Type == forwardFlag) &&
			d.Format == "" {
			d.Format = jsonFlag
		}

		if (d.Type == webhookFlag || d.Type == forwardFlag) &&
			d.Url == "" {
			return MandatoryDestinationFieldError(d.Type, d.Name)
		}

		if d.Format != jsonFlag && d.Format != tableFlag &&
			!strings.HasPrefix(d.Format, gotemplatePrefix) {
			return InvalidDestinationFieldError("format", d.Format, d.Name)
		}

		if d.Type != "file" && d.Type != webhookFlag && d.Type != forwardFlag {
			return InvalidDestinationFieldError("type", d.Type, d.Name)
		}

		if d.Type == "file" {
			d.File = os.Stdout

			if d.Path != "stdout" && d.Path != "" {
				outputFile, err := CreateOutputFile(d.Path)
				if err != nil {
					return err
				}

				d.File = outputFile
			}
		}
	}

	return nil
}

// parseStreamFlag parses the given stream flag and sets it in the given existing map.
func parseStreamFlag(flag string, existing map[string]*config.Stream,
	destinations map[string]*config.Destination) error {
	parts := strings.SplitN(flag, "=", 2)
	if len(parts) < 2 {
		return StreamFlagIncorrect(flag)
	}
	flagValue := parts[1]

	flagNameParts := strings.Split(parts[0], ".")
	if len(flagNameParts) < 3 || len(flagNameParts) > 4 {
		return StreamFlagIncorrect(flag)
	}

	if flagNameParts[0] != "streams" {
		return WrongFunctionInvocationError("parseStreamFlag()", flag)
	}

	if _, ok := existing[flagNameParts[1]]; !ok {
		conf := config.Stream{
			Name: flagNameParts[1],
		}

		existing[flagNameParts[1]] = &conf
	}

	streamConfig := existing[flagNameParts[1]]

	switch flagNameParts[2] {
	case "destinations":
		destinationNames := strings.Split(flagValue, ",")
		for _, destinationName := range destinationNames {
			destinationConfig, ok := destinations[destinationName]
			if !ok {
				return DestinationNotFoundError(destinationName, streamConfig.Name)
			}

			streamConfig.Destinations = append(streamConfig.Destinations, *destinationConfig)
		}
	case "filters":
		if len(flagNameParts) != 4 {
			return StreamFlagIncorrect(flag)
		}

		switch flagNameParts[3] {
		case "events":
			streamConfig.Filters.Events = strings.Split(flagValue, ",")
		case "policies":
			streamConfig.Filters.Policies = strings.Split(flagValue, ",")
		}
	case "buffer":
		if len(flagNameParts) != 4 {
			return StreamFlagIncorrect(flag)
		}

		switch flagNameParts[3] {
		case "mode":
			if flagValue != string(config.StreamBufferBlock) && flagValue != string(config.StreamBufferDrop) {
				return StreamFlagIncorrect(flag)
			}

			streamConfig.Buffer.Mode = config.StreamBufferMode(flagValue)
		case "size":
			size, err := strconv.Atoi(flagValue)
			if err != nil {
				return StreamFlagIncorrect(flag)
			}

			streamConfig.Buffer.Size = size
		}
	default:
		return StreamFlagIncorrect(flag)
	}

	return nil
}

// getWebhookFormat returns the format of the given webhook URL.
func getWebhookFormat(webhookUrl string) string {
	urlParts := strings.Split(webhookUrl, "?")
	if len(urlParts) == 1 || urlParts[1] == "" {
		return jsonFlag
	}

	queryParams := strings.SplitSeq(urlParts[1], "&")
	for part := range queryParams {
		if strings.HasPrefix(part, "gotemplate") {
			return part
		}
	}

	return jsonFlag
}

// PreparePrinterConfig prepares the printer config from the given printer kind and output path.
func PreparePrinterConfig(printerKind string, outputPath string) (config.Destination, error) {
	if printerKind == "ignore" {
		return config.Destination{
			Name: "ignore",
			Type: printerKind,
			Path: "stdout", // here because tests expect `stdout` as a default value but I believe it can be removed
		}, nil
	}

	var dest config.Destination
	outFile := os.Stdout
	var err error

	isFile := outputPath != "" && printerKind != forwardFlag && printerKind != webhookFlag

	if printerKind == webhookFlag {
		dest.Format = getWebhookFormat(outputPath)
	}

	dest.Type = printerKind
	dest.Url = outputPath
	dest.Name = outputPath + printerKind

	if isFile {
		if outputPath != "stdout" {
			outFile, err = CreateOutputFile(outputPath)
			if err != nil {
				return config.Destination{}, err
			}
		}

		dest.File = outFile
		dest.Format = printerKind
		dest.Path = outputPath
		dest.Type = "file"
		dest.Url = "" // clear unused URL
	}

	return dest, nil
}

// SetOption sets the given option in the given config
func SetOption(cfg *config.OutputConfig, option string) error {
	switch option {
	case stackAddressesFlag:
		cfg.StackAddresses = true
	case execEnvFlag:
		cfg.ExecEnv = true
	case parseArgumentsFlag:
		cfg.ParseArguments = true
	case parseArgumentsFDsFlag:
		cfg.ParseArgumentsFDs = true
		cfg.ParseArguments = true // no point in parsing file descriptor args only
	case sortEventsFlag:
		cfg.EventsSorting = true
	default:
		if strings.HasPrefix(option, "exec-hash") {
			hashExecParts := strings.Split(option, "=")
			if len(hashExecParts) == 1 {
				if option != "exec-hash" {
					goto invalidOption
				}
				// default
				cfg.CalcHashes = digest.CalcHashesDevInode
			} else if len(hashExecParts) == 2 {
				hashExecOpt := hashExecParts[1]
				switch hashExecOpt {
				case "none":
					cfg.CalcHashes = digest.CalcHashesNone
				case "inode":
					cfg.CalcHashes = digest.CalcHashesInode
				case "dev-inode":
					cfg.CalcHashes = digest.CalcHashesDevInode
				case "digest-inode":
					cfg.CalcHashes = digest.CalcHashesDigestInode
				default:
					goto invalidOption
				}
			} else {
				goto invalidOption
			}

			return nil
		}

	invalidOption:
		return InvalidOutputOptionError(option)
	}

	return nil
}

// getDestinationConfigs returns a slice of printer.Configs based on the given printerMap
func getDestinationConfigs(printerMap map[string]string, traceeConfig *config.OutputConfig,
	containerMode config.ContainerMode) ([]config.Destination, error) {
	printerConfigs := make([]config.Destination, 0, len(printerMap))

	for outPath, printerKind := range printerMap {
		if printerKind == "ignore" {
			continue
		}

		if printerKind == tableFlag {
			if err := SetOption(traceeConfig, parseArgumentsFlag); err != nil {
				return nil, err
			}
		}

		printerCfg, err := PreparePrinterConfig(printerKind, outPath)
		if err != nil {
			return nil, err
		}

		printerCfg.ContainerMode = containerMode

		printerConfigs = append(printerConfigs, printerCfg)
	}

	return printerConfigs, nil
}

// parseFormat parses the given format and sets it in the given printerMap
func parseFormat(outputParts []string, printerMap map[string]string) error {
	// if not file was passed, we use stdout
	if len(outputParts) == 1 {
		outputParts = append(outputParts, "stdout")
	}

	for _, outPath := range strings.Split(outputParts[1], ",") {
		if outPath == "" {
			return EmptyOutputFlagError("format")
		}

		if _, ok := printerMap[outPath]; ok {
			return DuplicateOutputPathError(outPath)
		}
		printerMap[outPath] = outputParts[0]
	}

	return nil
}

// parseOption parses the given option and sets it in the given config
func parseOption(outputParts []string, traceeConfig *config.OutputConfig) error {
	if len(outputParts) == 1 || outputParts[1] == "" {
		return EmptyOutputFlagError("option")
	}

	for _, option := range strings.Split(outputParts[1], ",") {
		err := SetOption(traceeConfig, option)
		if err != nil {
			return err
		}
	}

	return nil
}

// creates *os.File for the given path
func CreateOutputFile(path string) (*os.File, error) {
	fileInfo, err := os.Stat(path)
	if err == nil && fileInfo.IsDir() {
		return nil, errfmt.Errorf("cannot use a path of existing directory %s", path)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, errfmt.Errorf("failed to create directory: %v", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, errfmt.Errorf("failed to create output path: %v", err)
	}

	return file, nil
}

// validateURL validates the given URL
// --output [webhook|forward]:[protocol://user:pass@]host:port[?k=v#f]
func validateURL(outputParts []string, flag string) error {
	if len(outputParts) == 1 || outputParts[1] == "" {
		return EmptyOutputFlagError(flag)
	}
	// Now parse our URL using the standard library and report any errors from basic parsing.
	_, err := url.ParseRequestURI(outputParts[1])

	if err != nil {
		return InvalidOutputURIError(flag, outputParts[1])
	}

	return nil
}
