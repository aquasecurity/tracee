package trace

import (
	"os"

	cli "github.com/urfave/cli/v2"
	"gopkg.in/yaml.v2"
)

type Config struct {
	ListenAddr string `yaml:"listen_addr"`
	Metrics    bool   `yaml:"metrics"`
	Healthz    bool   `yaml:"healthz"`
	PProf      bool   `yaml:"pprof"`
	Debug      bool   `yaml:"debug"`
	Format     string `yaml:"format"`

	Collect struct {
		Capture struct {
			FileWrites bool `yaml:"file_write"`
			ModuleLoad bool `yaml:"module_load"`
		}

		Cache struct {
			Type string `yaml:"type"`
			Size int    `yaml:"size"`
		}

		ContainerEnrichment bool     `yaml:"container_enrichment"`
		PerfBufferSize      int      `yaml:"perf_buffer_size"`
		BlobPerfBufferSize  int      `yaml:"blob_perf_buffer_size"`
		ContainerRuntimes   []string `yaml:"crs"`

		Capabilities struct {
			AllowHighCapabilities bool     `yaml:"allow_high_capabilities"`
			Enable                bool     `yaml:"enable"`
			Add                   []string `yaml:"add"`
			Drop                  []string `yaml:"drop"`
		}
	}

	Rules struct {
		Rego struct {
			PartialEval   bool   `yaml:"partial_eval"`
			Aio           bool   `yaml:"aio"`
			RuntimeTarget string `yaml:"runtime_target"`
		}
		BufferSize     int      `yaml:"buffer_size"`
		Signatures     []string `yaml:"signatures"`
		Dir            string   `yaml:"dir"`
		OutputTemplate string   `yaml:"output_template"`
		Webhook        struct {
			Endpoint    string `yaml:"endpoint"`
			Template    string `yaml:"template"`
			ContentType string `yaml:"content_type"`
		}
		AllowHighCapabilities bool `yaml:"allow_high_capabilities"`
	}
}

func ConfigFromFile(file string) (Config, error) {
	var config Config

	data, err := os.ReadFile(file)
	if err != nil {
		return config, err
	}

	err = yaml.Unmarshal([]byte(data), &config)

	return config, err
}

func ConfigFromFlags(ctx *cli.Context) (Config, error) {
	var config Config

	config.ListenAddr = ctx.String("listen-addr")
	config.Metrics = ctx.Bool("metrics")
	config.Healthz = ctx.Bool("healthz")
	config.PProf = ctx.Bool("pprof")
	config.Debug = ctx.Bool("debut")

	//config.Collect.Capture.FileWrites =
	//config.Collect.Capture.ModuleLoad =

	//config.Collect.Capture.Cache.Type =
	//config.Collect.Capture.Cache.Size =

	config.Collect.ContainerEnrichment = ctx.Bool("containers")
	config.Collect.PerfBufferSize = ctx.Int("perf-buffer-size")
	config.Collect.BlobPerfBufferSize = ctx.Int("blob-perf-buffer-size")
	config.Collect.ContainerRuntimes = ctx.StringSlice("crs")

	//config.Collect.Capabilities.AllowHighCapabilities =
	//config.Collect.Capabilities.Enable =
	//config.Collect.Capabilities.Add =
	//config.Collect.Capabilities.Drop =

	config.Rules.Rego.PartialEval = ctx.Bool("rego-partial-eval")
	config.Rules.Rego.Aio = ctx.Bool("rego-aio")
	config.Rules.Rego.RuntimeTarget = ctx.String("rego-runtime-target")

	config.Rules.BufferSize = ctx.Int("sig-buffer")
	config.Rules.Signatures = ctx.StringSlice("rules")
	config.Rules.Dir = ctx.String("rules-dir")
	config.Rules.OutputTemplate = ctx.String("output-template")
	config.Rules.AllowHighCapabilities = ctx.Bool("allow-high-capabilities-for-rules")
	config.Rules.Webhook.Endpoint = ctx.String("webhook")
	config.Rules.Webhook.Template = ctx.String("webhook-template")
	config.Rules.Webhook.ContentType = ctx.String("webhook-content-type")

	return config, nil
}
