package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

type CliConfig struct {
	RegoConfig struct {
		Aio               bool   `json:"aio"`
		EnableParsedEvent bool   `json:"enabledParsedEvent"`
		PartialEval       bool   `json:"partialEval"`
		RunTimeTarget     string `json:"runtimeTarget"`
	} `json:"regoConfig"`
	Rules struct {
		InputDirectory string   `json:"inputDirectory"`
		RuleIds        []string `json:"rulesIds"`
	} `json:"rules"`
	Webhook struct {
		Url         string `json:"url"`
		Template    string `json:"template"`
		ContentType string `json:"contentType"`
	} `json:"webhook"`
	Input struct {
		File   string `json:"file"`
		Format string `json:"format"`
	} `json:"input"`
	Output struct {
		Template string `json:"template"`
	} `json:"output"`
	Pprof struct {
		Enable  bool   `json:"enable"`
		Address string `json:"address"`
	} `json:"pprof"`
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
