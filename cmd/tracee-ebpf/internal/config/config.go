package config

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

type TraceeEbpfCliConfig struct {
	PerfRingBuffers struct {
		EventSubmitBufferSize int
		BlobBufferSize        int
	}
	VerboseDebug bool
	InstallPath  string
	BuildPolicy  string
	Trace        []string
	Output       []string
	Capture      []string
}

func Load(fileName string) (config *TraceeEbpfCliConfig, err error) {
	cfgFile, err := os.Open(fileName)

	if err != nil {
		return nil, err
	}

	defer cfgFile.Close()

	byteValue, err := ioutil.ReadAll(cfgFile)

	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(byteValue, &config)

	return config, err
}

func DefaultConfigLocation() string {
	envLocation := os.Getenv("TRACEE_EBPF_CONFIG")
	if envLocation != "" {
		return envLocation
	}
	return "./tracee-ebpf-config.json"
}

func (c *TraceeEbpfCliConfig) DefaultInstallPath() string {
	if c.InstallPath != "" {
		return c.InstallPath
	}
	return "/tmp/tracee"
}

func (c *TraceeEbpfCliConfig) DefaultBuildPolicy() string {
	if c.BuildPolicy != "" {
		return c.BuildPolicy
	}
	return "if-needed"
}

func (c *TraceeEbpfCliConfig) DefaultEventSubmitBufferSize() int {
	bufferSize := c.PerfRingBuffers.EventSubmitBufferSize
	if bufferSize != 0 {
		return bufferSize
	}
	return 1024
}

func (c *TraceeEbpfCliConfig) DefaultBlobBufferSize() int {
	bufferSize := c.PerfRingBuffers.BlobBufferSize
	if bufferSize != 0 {
		return bufferSize
	}
	return 1024
}
