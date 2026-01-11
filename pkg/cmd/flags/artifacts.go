package flags

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/config"
)

const (
	ArtifactsFlag = "artifacts"

	// Artifact option names
	fileWrite     = "file-write"
	fileRead      = "file-read"
	executable    = "executable"
	kernelModules = "kernel-modules"
	bpfPrograms   = "bpf-programs"
	memoryRegions = "memory-regions"
	network       = "network"
	dir           = "dir"

	// Artifact sub-options
	enabled    = "enabled"
	filtersKey = "filters"
	clear      = "clear"
	pathKey    = "path"

	// Network pcap options
	pcap        = "pcap"
	pcapSplit   = "split"
	pcapOptions = "options"
	pcapSnaplen = "snaplen"

	// Default values
	defaultArtifactsDir = "/tmp/tracee"
	defaultPcapLength   = 96

	artifactsInvalidOptionFormat = "invalid artifacts option: %s, run 'tracee man artifacts' for more info"
)

// invalidArtifactsOptionError returns an error for an invalid artifacts option.
func invalidArtifactsOptionError(opt string) error {
	return errfmt.Errorf(artifactsInvalidOptionFormat, opt)
}

// ArtifactsConfig is the configuration for artifacts capture.
type ArtifactsConfig struct {
	FileWrite     FileWriteConfig `mapstructure:"file-write"`
	FileRead      FileReadConfig  `mapstructure:"file-read"`
	Executable    bool            `mapstructure:"executable"`
	KernelModules bool            `mapstructure:"kernel-modules"`
	BpfPrograms   bool            `mapstructure:"bpf-programs"`
	MemoryRegions bool            `mapstructure:"memory-regions"`
	Network       NetworkConfig   `mapstructure:"network"`
	Dir           DirConfig       `mapstructure:"dir"`
}

// FileWriteConfig is the configuration for file write capture.
type FileWriteConfig struct {
	Enabled    bool                     `mapstructure:"enabled"`
	Filters    []string                 `mapstructure:"filters"`
	PathFilter []string                 `mapstructure:"-"`
	TypeFilter config.FileArtifactsType `mapstructure:"-"`
}

// FileReadConfig is the configuration for file read capture.
type FileReadConfig struct {
	Enabled    bool                     `mapstructure:"enabled"`
	Filters    []string                 `mapstructure:"filters"`
	PathFilter []string                 `mapstructure:"-"`
	TypeFilter config.FileArtifactsType `mapstructure:"-"`
}

// NetworkConfig is the configuration for network capture.
type NetworkConfig struct {
	Enabled          bool              `mapstructure:"enabled"`
	Pcap             NetworkPcapConfig `mapstructure:"pcap"`
	CaptureSingle    bool              `mapstructure:"-"`
	CaptureProcess   bool              `mapstructure:"-"`
	CaptureContainer bool              `mapstructure:"-"`
	CaptureCommand   bool              `mapstructure:"-"`
	CaptureFiltered  bool              `mapstructure:"-"`
	CaptureLength    uint32            `mapstructure:"-"`
}

// NetworkPcapConfig is used for YAML unmarshaling only.
type NetworkPcapConfig struct {
	Split   string `mapstructure:"split"`
	Options string `mapstructure:"options"`
	Snaplen string `mapstructure:"snaplen"`
}

// DirConfig is the configuration for artifacts directory.
type DirConfig struct {
	Path  string `mapstructure:"path"`
	Clear bool   `mapstructure:"clear"`
}

// GetArtifactsConfig returns the artifacts configuration.
func (a *ArtifactsConfig) GetArtifactsConfig() config.ArtifactsConfig {
	artifacts := config.ArtifactsConfig{}

	// Set output path
	outDir := defaultArtifactsDir
	if a.Dir.Path != "" {
		outDir = a.Dir.Path
	}
	artifacts.OutputPath = filepath.Join(outDir, "out")

	// File write - just copy the already-parsed data
	if a.FileWrite.Enabled {
		artifacts.FileWrite.Capture = true
		artifacts.FileWrite.PathFilter = a.FileWrite.PathFilter
		artifacts.FileWrite.TypeFilter = a.FileWrite.TypeFilter
	}

	// File read - just copy the already-parsed data
	if a.FileRead.Enabled {
		artifacts.FileRead.Capture = true
		artifacts.FileRead.PathFilter = a.FileRead.PathFilter
		artifacts.FileRead.TypeFilter = a.FileRead.TypeFilter
	}

	// Executable
	artifacts.Exec = a.Executable

	// Kernel modules
	artifacts.Module = a.KernelModules

	// BPF programs
	artifacts.Bpf = a.BpfPrograms

	// Memory regions
	artifacts.Mem = a.MemoryRegions

	// Network - just copy the already-parsed data
	if a.Network.Enabled {
		artifacts.Net.CaptureSingle = a.Network.CaptureSingle
		artifacts.Net.CaptureProcess = a.Network.CaptureProcess
		artifacts.Net.CaptureContainer = a.Network.CaptureContainer
		artifacts.Net.CaptureCommand = a.Network.CaptureCommand
		artifacts.Net.CaptureFiltered = a.Network.CaptureFiltered
		artifacts.Net.CaptureLength = a.Network.CaptureLength
	}

	// Clear dir if needed
	if a.Dir.Clear {
		if err := os.RemoveAll(artifacts.OutputPath); err != nil {
			logger.Warnw("Removing all", "error", err)
		}
	}

	return artifacts
}

// flags returns the flags for the artifacts configuration.
func (a *ArtifactsConfig) flags() []string {
	flags := []string{}

	// file-write: if Enabled is true OR any filters are set, add file-write flag
	if a.FileWrite.Enabled || len(a.FileWrite.Filters) > 0 || len(a.FileWrite.PathFilter) > 0 {
		flags = append(flags, fileWrite)
	}
	// Output filters from Filters field (for structured configs) or reconstruct from PathFilter/TypeFilter
	if len(a.FileWrite.Filters) > 0 {
		for _, filter := range a.FileWrite.Filters {
			flags = append(flags, fmt.Sprintf("%s.%s=%s", fileWrite, filtersKey, filter))
		}
	} else {
		// Reconstruct from parsed data (for CLI flags that were parsed)
		for _, pathFilter := range a.FileWrite.PathFilter {
			flags = append(flags, fmt.Sprintf("%s.%s=path=%s*", fileWrite, filtersKey, pathFilter))
		}
		// Note: TypeFilter is a bitmask, so we can't easily reconstruct the original filter strings
		// This is a limitation when converting from parsed data back to flags
	}

	// file-read: if Enabled is true OR any filters are set, add file-read flag
	if a.FileRead.Enabled || len(a.FileRead.Filters) > 0 || len(a.FileRead.PathFilter) > 0 {
		flags = append(flags, fileRead)
	}
	// Output filters from Filters field (for structured configs) or reconstruct from PathFilter/TypeFilter
	if len(a.FileRead.Filters) > 0 {
		for _, filter := range a.FileRead.Filters {
			flags = append(flags, fmt.Sprintf("%s.%s=%s", fileRead, filtersKey, filter))
		}
	} else {
		// Reconstruct from parsed data (for CLI flags that were parsed)
		for _, pathFilter := range a.FileRead.PathFilter {
			flags = append(flags, fmt.Sprintf("%s.%s=path=%s*", fileRead, filtersKey, pathFilter))
		}
		// Note: TypeFilter is a bitmask, so we can't easily reconstruct the original filter strings
	}

	// executable
	if a.Executable {
		flags = append(flags, executable)
	}

	// kernel-modules
	if a.KernelModules {
		flags = append(flags, kernelModules)
	}

	// bpf-programs
	if a.BpfPrograms {
		flags = append(flags, bpfPrograms)
	}

	// memory-regions
	if a.MemoryRegions {
		flags = append(flags, memoryRegions)
	}

	// network: if Enabled is true OR any pcap options are set, add network flag
	if a.Network.Enabled || a.Network.Pcap.Split != "" || a.Network.Pcap.Options != "" ||
		a.Network.Pcap.Snaplen != "" || a.Network.CaptureProcess || a.Network.CaptureContainer ||
		a.Network.CaptureCommand || a.Network.CaptureFiltered || a.Network.CaptureLength != 0 {
		flags = append(flags, network)
		// Output from Pcap field (for structured configs) or reconstruct from parsed fields
		if a.Network.Pcap.Split != "" {
			flags = append(flags, fmt.Sprintf("%s.%s.%s=%s", network, pcap, pcapSplit, a.Network.Pcap.Split))
		} else {
			// Reconstruct split flags from parsed data
			// Only output if split was explicitly set (CaptureSingle=false means split was set to non-single)
			// or if other capture flags are set
			hasOtherFlags := a.Network.CaptureProcess || a.Network.CaptureContainer || a.Network.CaptureCommand
			if !a.Network.CaptureSingle || hasOtherFlags {
				var splitParts []string
				if a.Network.CaptureSingle {
					splitParts = append(splitParts, "single")
				}
				if a.Network.CaptureProcess {
					splitParts = append(splitParts, "process")
				}
				if a.Network.CaptureContainer {
					splitParts = append(splitParts, "container")
				}
				if a.Network.CaptureCommand {
					splitParts = append(splitParts, "command")
				}
				if len(splitParts) > 0 {
					flags = append(flags, fmt.Sprintf("%s.%s.%s=%s", network, pcap, pcapSplit, strings.Join(splitParts, ",")))
				}
			}
		}
		// Output options
		if a.Network.Pcap.Options != "" {
			flags = append(flags, fmt.Sprintf("%s.%s.%s=%s", network, pcap, pcapOptions, a.Network.Pcap.Options))
		} else if a.Network.CaptureFiltered {
			flags = append(flags, fmt.Sprintf("%s.%s.%s=filtered", network, pcap, pcapOptions))
		}
		// Output snaplen
		if a.Network.Pcap.Snaplen != "" {
			flags = append(flags, fmt.Sprintf("%s.%s.%s=%s", network, pcap, pcapSnaplen, a.Network.Pcap.Snaplen))
		} else if a.Network.CaptureLength != defaultPcapLength && a.Network.CaptureLength != 0 {
			snaplenStr := formatPcapSnaplen(a.Network.CaptureLength)
			if snaplenStr != "" {
				flags = append(flags, fmt.Sprintf("%s.%s.%s=%s", network, pcap, pcapSnaplen, snaplenStr))
			}
		}
	}

	// dir
	if a.Dir.Path != "" {
		flags = append(flags, fmt.Sprintf("%s.%s=%s", dir, pathKey, a.Dir.Path))
	}
	if a.Dir.Clear {
		flags = append(flags, fmt.Sprintf("%s.%s", dir, clear))
	}

	return flags
}

// PrepareArtifacts prepares the artifacts configuration from the artifacts options.
func PrepareArtifacts(artifactsSlice []string) (ArtifactsConfig, error) {
	artifacts := ArtifactsConfig{}

	for _, opt := range artifactsSlice {
		// Split by "." to get the main option and sub-options
		parts := strings.SplitN(opt, ".", 2)
		mainOpt := parts[0]
		var subOpt string
		if len(parts) > 1 {
			subOpt = parts[1]
		}

		switch mainOpt {
		case fileWrite:
			// If no sub-option, it's a boolean flag (enable file-write)
			if subOpt == "" {
				artifacts.FileWrite.Enabled = true
			} else {
				err := parseFileArtifactOptionWrite(&artifacts.FileWrite, subOpt)
				if err != nil {
					return ArtifactsConfig{}, err
				}
			}
		case fileRead:
			// If no sub-option, it's a boolean flag (enable file-read)
			if subOpt == "" {
				artifacts.FileRead.Enabled = true
			} else {
				err := parseFileArtifactOptionRead(&artifacts.FileRead, subOpt)
				if err != nil {
					return ArtifactsConfig{}, err
				}
			}
		case executable:
			// If no sub-option, it's a boolean flag (enable executable)
			if subOpt != "" {
				return ArtifactsConfig{}, invalidArtifactsOptionError(opt)
			}
			artifacts.Executable = true
		case kernelModules:
			// If no sub-option, it's a boolean flag (enable kernel-modules)
			if subOpt != "" {
				return ArtifactsConfig{}, invalidArtifactsOptionError(opt)
			}
			artifacts.KernelModules = true
		case bpfPrograms:
			// If no sub-option, it's a boolean flag (enable bpf-programs)
			if subOpt != "" {
				return ArtifactsConfig{}, invalidArtifactsOptionError(opt)
			}
			artifacts.BpfPrograms = true
		case memoryRegions:
			// If no sub-option, it's a boolean flag (enable memory-regions)
			if subOpt != "" {
				return ArtifactsConfig{}, invalidArtifactsOptionError(opt)
			}
			artifacts.MemoryRegions = true
		case network:
			// If no sub-option, it's a boolean flag (enable network)
			if subOpt == "" {
				artifacts.Network.Enabled = true
				artifacts.Network.CaptureSingle = true
				artifacts.Network.CaptureLength = defaultPcapLength
			} else {
				err := parseNetworkArtifactOption(&artifacts.Network, subOpt)
				if err != nil {
					return ArtifactsConfig{}, err
				}
			}
		case dir:
			err := parseDirArtifactOption(&artifacts.Dir, subOpt)
			if err != nil {
				return ArtifactsConfig{}, err
			}
		default:
			return ArtifactsConfig{}, invalidArtifactsOptionError(opt)
		}
	}

	// Parse filters from Filters field (for structured configs that came through GetFlagsFromViper)
	// This happens after all options are processed
	if len(artifacts.FileWrite.Filters) > 0 {
		for _, filter := range artifacts.FileWrite.Filters {
			var artifactsConfig config.FileArtifactsConfig
			if err := parseFileArtifactsSubOption(filter, &artifactsConfig); err != nil {
				return ArtifactsConfig{}, errfmt.WrapError(err)
			}
			artifacts.FileWrite.PathFilter = append(artifacts.FileWrite.PathFilter, artifactsConfig.PathFilter...)
			artifacts.FileWrite.TypeFilter |= artifactsConfig.TypeFilter
		}
		artifacts.FileWrite.Filters = nil // Clear after parsing
	}

	if len(artifacts.FileRead.Filters) > 0 {
		for _, filter := range artifacts.FileRead.Filters {
			var artifactsConfig config.FileArtifactsConfig
			if err := parseFileArtifactsSubOption(filter, &artifactsConfig); err != nil {
				return ArtifactsConfig{}, errfmt.WrapError(err)
			}
			artifacts.FileRead.PathFilter = append(artifacts.FileRead.PathFilter, artifactsConfig.PathFilter...)
			artifacts.FileRead.TypeFilter |= artifactsConfig.TypeFilter
		}
		artifacts.FileRead.Filters = nil // Clear after parsing
	}

	// Parse network pcap config from Pcap field (for structured configs)
	if artifacts.Network.Pcap.Split != "" {
		artifacts.Network.CaptureSingle = false
		fields := strings.Split(artifacts.Network.Pcap.Split, ",")
		for _, field := range fields {
			field = strings.TrimSpace(field)
			switch field {
			case "single":
				artifacts.Network.CaptureSingle = true
			case "process":
				artifacts.Network.CaptureProcess = true
			case "container":
				artifacts.Network.CaptureContainer = true
			case "command":
				artifacts.Network.CaptureCommand = true
			}
		}
		if artifacts.Network.CaptureLength == 0 {
			artifacts.Network.CaptureLength = defaultPcapLength
		}
	}

	if artifacts.Network.Pcap.Options != "" {
		switch strings.ToLower(artifacts.Network.Pcap.Options) {
		case "filtered":
			artifacts.Network.CaptureFiltered = true
		case "none":
			artifacts.Network.CaptureFiltered = false
		}
	}

	if artifacts.Network.Pcap.Snaplen != "" {
		amount, err := parsePcapSnaplen(artifacts.Network.Pcap.Snaplen)
		if err != nil {
			return ArtifactsConfig{}, errfmt.WrapError(err)
		}
		if amount > math.MaxUint32 {
			return ArtifactsConfig{}, errfmt.Errorf("pcap snaplen value %d exceeds uint32 maximum", amount)
		}
		artifacts.Network.CaptureLength = uint32(amount)
	}

	return artifacts, nil
}

// parseFileArtifactsSubOption parses file artifacts sub-options in the format '<sub-opt>=<value>'.
// This is shared logic between the legacy capture flag and the new artifacts flag.
func parseFileArtifactsSubOption(option string, artifactsConfig *config.FileArtifactsConfig) error {
	optAndValue := strings.SplitN(option, "=", 2)
	if len(optAndValue) != 2 || len(optAndValue[1]) == 0 {
		return errfmt.Errorf("invalid file capture option format: %s", option)
	}
	opt := optAndValue[0]
	value := optAndValue[1]
	switch opt {
	case "path":
		if !strings.HasSuffix(option, "*") {
			return errfmt.Errorf("file path filter should end with *")
		}
		pathPrefix := strings.TrimSuffix(value, "*")
		if len(pathPrefix) == 0 {
			return errfmt.Errorf("artifacts path filter cannot be empty")
		}
		artifactsConfig.PathFilter = append(artifactsConfig.PathFilter, pathPrefix)
	case "type":
		typeFilter := strings.TrimPrefix(option, "type=")
		filterFlag, err := parseFileArtifactsType(typeFilter)
		if err != nil {
			return err
		}
		artifactsConfig.TypeFilter |= filterFlag
	case "fd":
		typeFilter := strings.TrimPrefix(option, "fd=")
		filterFlag, err := parseFileArtifactsFDs(typeFilter)
		if err != nil {
			return err
		}
		artifactsConfig.TypeFilter |= filterFlag
	default:
		return errfmt.Errorf("unrecognized file artifacts option: %s", opt)
	}

	return nil
}

var artifactsFileTypeStringToFlag = map[string]config.FileArtifactsType{
	"pipe":    config.ArtifactsPipeFiles,
	"socket":  config.ArtifactsSocketFiles,
	"regular": config.ArtifactsRegularFiles,
	"elf":     config.ArtifactsELFFiles,
}

// parseFileArtifactsType parses file type string to its matching bit-flag value.
func parseFileArtifactsType(filter string) (config.FileArtifactsType, error) {
	filterFlag, ok := artifactsFileTypeStringToFlag[filter]
	if ok {
		return filterFlag, nil
	}
	return 0, errfmt.Errorf("unsupported file type filter value for artifacts - %s", filter)
}

var artifactsFDsStringToFlag = map[string]config.FileArtifactsType{
	"stdin":  config.ArtifactsStdinFiles,
	"stdout": config.ArtifactsStdoutFiles,
	"stderr": config.ArtifactsStderrFiles,
}

// parseFileArtifactsFDs parses file standard FD string to its matching bit-flag value.
func parseFileArtifactsFDs(filter string) (config.FileArtifactsType, error) {
	filterFlag, ok := artifactsFDsStringToFlag[filter]
	if ok {
		return filterFlag, nil
	}
	return 0, errfmt.Errorf("unsupported file FD filter value for artifacts - %s", filter)
}

// parseFileArtifactOptionWrite parses file-write artifact options.
func parseFileArtifactOptionWrite(fileConfig *FileWriteConfig, subOpt string) error {
	if strings.HasPrefix(subOpt, filtersKey+"=") {
		// Setting filters automatically enables file-write
		fileConfig.Enabled = true
		filterStr := strings.TrimPrefix(subOpt, filtersKey+"=")
		if filterStr == "" {
			return errfmt.Errorf("file write filter cannot be empty")
		}
		// Parse filter immediately and store in the config
		var artifactsConfig config.FileArtifactsConfig
		if err := parseFileArtifactsSubOption(filterStr, &artifactsConfig); err != nil {
			return errfmt.WrapError(err)
		}
		// Merge the parsed filter into fileConfig
		fileConfig.PathFilter = append(fileConfig.PathFilter, artifactsConfig.PathFilter...)
		fileConfig.TypeFilter |= artifactsConfig.TypeFilter
		return nil
	}

	return errfmt.Errorf("invalid file write option: %s", subOpt)
}

// parseFileArtifactOptionRead parses file-read artifact options.
func parseFileArtifactOptionRead(fileConfig *FileReadConfig, subOpt string) error {
	if strings.HasPrefix(subOpt, filtersKey+"=") {
		// Setting filters automatically enables file-read
		fileConfig.Enabled = true
		filterStr := strings.TrimPrefix(subOpt, filtersKey+"=")
		if filterStr == "" {
			return errfmt.Errorf("file read filter cannot be empty")
		}
		// Parse filter immediately and store in the config
		var artifactsConfig config.FileArtifactsConfig
		if err := parseFileArtifactsSubOption(filterStr, &artifactsConfig); err != nil {
			return errfmt.WrapError(err)
		}
		// Merge the parsed filter into fileConfig
		fileConfig.PathFilter = append(fileConfig.PathFilter, artifactsConfig.PathFilter...)
		fileConfig.TypeFilter |= artifactsConfig.TypeFilter
		return nil
	}

	return errfmt.Errorf("invalid file read option: %s", subOpt)
}

// parseNetworkArtifactOption parses network artifact options.
func parseNetworkArtifactOption(netConfig *NetworkConfig, subOpt string) error {
	if strings.HasPrefix(subOpt, pcap+".") {
		// Setting pcap options automatically enables network
		netConfig.Enabled = true
		// Set defaults if not already set
		if !netConfig.CaptureSingle && !netConfig.CaptureProcess && !netConfig.CaptureContainer && !netConfig.CaptureCommand {
			netConfig.CaptureSingle = true
		}
		if netConfig.CaptureLength == 0 {
			netConfig.CaptureLength = defaultPcapLength
		}
		pcapOpt := strings.TrimPrefix(subOpt, pcap+".")
		pcapParts := strings.SplitN(pcapOpt, "=", 2)
		if len(pcapParts) != 2 {
			return errfmt.Errorf("invalid network pcap option: %s", subOpt)
		}

		pcapKey := pcapParts[0]
		pcapValue := pcapParts[1]

		switch pcapKey {
		case pcapSplit:
			// Parse split modes immediately
			netConfig.CaptureSingle = false // remove default mode
			fields := strings.Split(pcapValue, ",")
			for _, field := range fields {
				field = strings.TrimSpace(field)
				switch field {
				case "single":
					netConfig.CaptureSingle = true
				case "process":
					netConfig.CaptureProcess = true
				case "container":
					netConfig.CaptureContainer = true
				case "command":
					netConfig.CaptureCommand = true
				default:
					return errfmt.Errorf("invalid pcap split mode: %s", field)
				}
			}
			netConfig.CaptureLength = defaultPcapLength
		case pcapOptions:
			pcapValue = strings.ToLower(pcapValue)
			if pcapValue == "none" {
				netConfig.CaptureFiltered = false
			} else if pcapValue == "filtered" {
				netConfig.CaptureFiltered = true
			} else {
				return errfmt.Errorf("invalid pcap options value: %s (must be 'none' or 'filtered')", pcapValue)
			}
		case pcapSnaplen:
			// Parse snaplen immediately
			amount, err := parsePcapSnaplen(pcapValue)
			if err != nil {
				return errfmt.WrapError(err)
			}
			if amount > math.MaxUint32 {
				return errfmt.Errorf("pcap snaplen value %d exceeds uint32 maximum", amount)
			}
			netConfig.CaptureLength = uint32(amount)
		default:
			return errfmt.Errorf("invalid network pcap option: %s", pcapKey)
		}
		return nil
	}

	return errfmt.Errorf("invalid network option: %s", subOpt)
}

// parsePcapSnaplen parses pcap snaplen string to bytes.
func parsePcapSnaplen(snaplen string) (uint64, error) {
	var amount uint64
	var err error
	snaplenLower := strings.ToLower(snaplen)

	if snaplenLower == "default" {
		return defaultPcapLength, nil
	} else if snaplenLower == "max" {
		return (1 << 16) - 1, nil // max length for IP packets
	} else if snaplenLower == "headers" {
		return 0, nil // sets headers only length for capturing
	} else if strings.HasSuffix(snaplenLower, "kb") || strings.HasSuffix(snaplenLower, "k") {
		value := strings.TrimSuffix(snaplenLower, "kb")
		value = strings.TrimSuffix(value, "k")
		amount, err = strconv.ParseUint(value, 10, 64)
		if err != nil {
			return 0, errfmt.Errorf("could not parse pcap snaplen: %v", err)
		}
		amount *= 1024 // result in bytes
	} else if strings.HasSuffix(snaplenLower, "b") {
		value := strings.TrimSuffix(snaplenLower, "b")
		amount, err = strconv.ParseUint(value, 10, 64)
		if err != nil {
			return 0, errfmt.Errorf("could not parse pcap snaplen: %v", err)
		}
	} else {
		return 0, errfmt.Errorf("could not parse pcap snaplen: missing b or kb ?")
	}

	if amount >= (1 << 16) {
		amount = (1 << 16) - 1
	}
	return amount, nil
}

// formatPcapSnaplen formats pcap snaplen bytes to string format.
func formatPcapSnaplen(length uint32) string {
	if length == 0 {
		return "headers"
	}
	if length == defaultPcapLength {
		return "default"
	}
	if length == (1<<16)-1 {
		return "max"
	}
	if length%1024 == 0 {
		return fmt.Sprintf("%dkb", length/1024)
	}
	return fmt.Sprintf("%db", length)
}

// parseDirArtifactOption parses directory artifact options.
func parseDirArtifactOption(dirConfig *DirConfig, subOpt string) error {
	if subOpt == clear {
		dirConfig.Clear = true
		return nil
	}

	if strings.HasPrefix(subOpt, pathKey+"=") {
		pathValue := strings.TrimPrefix(subOpt, pathKey+"=")
		if len(pathValue) == 0 {
			return errfmt.Errorf("artifacts output dir cannot be empty")
		}
		dirConfig.Path = pathValue
		return nil
	}

	return errfmt.Errorf("invalid dir option: %s", subOpt)
}
