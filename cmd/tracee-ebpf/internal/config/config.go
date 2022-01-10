package config

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
)

type CliConfig struct {
	PerfRingBuffers struct {
		EventSubmitBufferSize int `json:"eventSubmitBufferSize"`
		BlobBufferSize        int `json:"blobBufferSize"`
	} `json:"perfRingBuffers"`
	VerboseDebug bool     `json:"verboseDebug"`
	InstallPath  string   `json:"installPath"`
	BuildPolicy  string   `json:"buildPolicy"`
	Trace        []string `json:"trace"`
	Output       []string `json:"output"`
	Capture      []string `json:"capture"`
}

func Load(fileName string) (config CliConfig, err error) {
	cfgFile, err := os.Open(fileName)

	if err != nil {
		return CliConfig{}, err
	}

	defer cfgFile.Close()

	byteValue, err := ioutil.ReadAll(cfgFile)

	if err != nil {
		return CliConfig{}, err
	}

	err = json.Unmarshal(byteValue, &config)

	return config, err
}

func DefaultConfigLocation() (string, error) {
	envLocation := os.Getenv("TRACEE_EBPF_CONFIG")
	if envLocation != "" {
		return envLocation, nil
	}
	return "", errors.New("configuration location not found in TRACEE_EBPF_CONFIG")
}

func (c *CliConfig) DefaultInstallPath() string {
	if c.InstallPath != "" {
		return c.InstallPath
	}
	return "/tmp/tracee"
}

func (c *CliConfig) DefaultBuildPolicy() string {
	if c.BuildPolicy != "" {
		return c.BuildPolicy
	}
	return "if-needed"
}

func (c *CliConfig) DefaultEventSubmitBufferSize() int {
	bufferSize := c.PerfRingBuffers.EventSubmitBufferSize
	if bufferSize != 0 {
		return bufferSize
	}
	return 1024
}

func (c *CliConfig) DefaultBlobBufferSize() int {
	bufferSize := c.PerfRingBuffers.BlobBufferSize
	if bufferSize != 0 {
		return bufferSize
	}
	return 1024
}
