package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

type CliConfig struct {
	RegoConfig struct {
		Aio               bool
		EnableParsedEvent bool
		PartialEval       bool
		RunTimeTarget     string
	}
	Rules struct {
		InputDirectory string
		RuleIds        []string
	}
	Webhook struct {
		Url         string
		Template    string
		ContentType string
	}
	Input struct {
		File   string
		Format string
	}
	Output struct {
		Template string
	}
	Pprof struct {
		Enable  bool
		Address string
	}
}

func Load(fileName string) (config *CliConfig, err error) {
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
	envLocation := os.Getenv("TRACEE_RULES_CONFIG")
	if envLocation != "" {
		return envLocation
	}
	return "./tracee-rules-config.json"
}

func (c *CliConfig) GetTraceeInputSlice() []string {
	if c.Input.File != "" && c.Input.Format != "" {
		return []string{fmt.Sprintf("file:%s", c.Input.File), fmt.Sprintf("format:%s", c.Input.Format)}
	}
	return []string{}
}

func (c *CliConfig) GetDefaultPprofAddress() string {
	if c.Pprof.Address != "" {
		return c.Pprof.Address
	}
	return ":7777"
}

func (c *CliConfig) GetDefaultRegoRuntime() string {
	if c.RegoConfig.RunTimeTarget != "" {
		return c.RegoConfig.RunTimeTarget
	}
	return "rego"
}
