package flags

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/common/errfmt"
)

const (
	BuffersFlag = "buffers"

	kernelEventsFlag       = "kernel.events"
	kernelArtifactsFlag    = "kernel.artifacts"
	kernelControlPlaneFlag = "kernel.control-plane"
	pipelineFlag           = "pipeline"

	invalidBuffersFlagError          = "invalid buffers flag: '%s', use 'trace man buffers' for more info"
	invalidBufferFlagPositiveInteger = "invalid buffer flag: %s value must be a positive integer, use 'trace man buffers' for more info"
	invalidBufferFlagNegativeOrZero  = "invalid buffer flag: %s value can't be negative or zero, use 'trace man buffers' for more info"
)

// BuffersConfig is a struct containing the buffers sizes
type BuffersConfig struct {
	Kernel   KernelBuffersConfig `mapstructure:"kernel"`
	Pipeline int                 `mapstructure:"pipeline"`
}

// KernelBuffersConfig holds kernel buffer sizes
type KernelBuffersConfig struct {
	Events       int `mapstructure:"events"`
	Artifacts    int `mapstructure:"artifacts"`
	ControlPlane int `mapstructure:"control-plane"`
}

// flags returns the flags for the buffers config
func (c *BuffersConfig) flags() []string {
	flags := make([]string, 0)

	if c.Kernel.Events != 0 {
		flags = append(flags, fmt.Sprintf("kernel.events=%d", c.Kernel.Events))
	}
	if c.Kernel.Artifacts != 0 {
		flags = append(flags, fmt.Sprintf("kernel.artifacts=%d", c.Kernel.Artifacts))
	}
	if c.Kernel.ControlPlane != 0 {
		flags = append(flags, fmt.Sprintf("kernel.control-plane=%d", c.Kernel.ControlPlane))
	}
	if c.Pipeline != 0 {
		flags = append(flags, fmt.Sprintf("pipeline=%d", c.Pipeline))
	}

	return flags
}

// PrepareBuffers prepares the buffers based on the flags
func PrepareBuffers(flags []string) (BuffersConfig, error) {
	// for the kernel events and kernel artifacts buffer the default is the amount of pages to accommodate 4MB (it will depend on the architecture).
	buffers := BuffersConfig{
		Kernel: KernelBuffersConfig{
			Events:       GetDefaultPerfBufferSize(),
			Artifacts:    GetDefaultPerfBufferSize(),
			ControlPlane: GetDefaultPerfBufferSize(),
		},
		Pipeline: 1_000,
	}

	for _, flag := range flags {
		values := strings.Split(flag, "=")

		if len(values) != 2 || values[0] == "" || values[1] == "" {
			return BuffersConfig{}, errfmt.Errorf(invalidBuffersFlagError, flag)
		}

		size, err := strconv.Atoi(values[1])
		if err != nil {
			return buffers, errfmt.Errorf(invalidBufferFlagPositiveInteger, values[0])
		}

		if size <= 0 {
			return buffers, errfmt.Errorf(invalidBufferFlagNegativeOrZero, values[0])
		}

		switch values[0] {
		case kernelEventsFlag:
			buffers.Kernel.Events = size
		case kernelArtifactsFlag:
			buffers.Kernel.Artifacts = size
		case kernelControlPlaneFlag:
			buffers.Kernel.ControlPlane = size
		case pipelineFlag:
			buffers.Pipeline = size
		default:
			return buffers, errfmt.Errorf(invalidBuffersFlagError, values[0])
		}
	}

	return buffers, nil
}

// GetDefaultPerfBufferSize returns the default perf buffer size in pages
// for the kernel events and kernel artifacts buffer the default is the amount of pages to accommodate 4MB of contigous spaces
// (it will depend on the architecture).
func GetDefaultPerfBufferSize() int {
	return (4096 * 1024) / os.Getpagesize()
}

// invalidBuffersFlagErrorMsg formats the error message for an invalid buffers flag.
func invalidBuffersFlagErrorMsg(flag string) string {
	return fmt.Sprintf(invalidBuffersFlagError, flag)
}

// invalidBufferFlagPositiveIntegerError formats the error message for a buffer flag with non-numeric value.
func invalidBufferFlagPositiveIntegerError(flagName string) string {
	return fmt.Sprintf(invalidBufferFlagPositiveInteger, flagName)
}

// invalidBufferFlagNegativeOrZeroError formats the error message for a buffer flag with negative or zero value.
func invalidBufferFlagNegativeOrZeroError(flagName string) string {
	return fmt.Sprintf(invalidBufferFlagNegativeOrZero, flagName)
}
