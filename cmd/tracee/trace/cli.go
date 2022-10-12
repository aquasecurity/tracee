package trace

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/tracee/cmd/tracee/collect/flags"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/server"
	"github.com/aquasecurity/tracee/pkg/signatures"

	cli "github.com/urfave/cli/v2"
)

var version string

func CLIAction() func(ctx *cli.Context) error {
	return func(ctx *cli.Context) error {
		if ctx.IsSet("config") && ctx.NumFlags() > 1 {
			return errors.New("Error using --config with other flags. The config flag cannot be used with other flags")
		}

		var config Config
		var err error
		if ctx.IsSet("config") {
			config, err = ConfigFromFile(ctx.String("config"))
		} else {
			config, err = ConfigFromFlags(ctx)
		}

		if err != nil {
			logger.Fatal("app", "error", err)
		}

		return trace(config)
	}
}

func CLIFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringSliceFlag{
			Name:    "capture",
			Aliases: []string{"c"},
			Value:   nil,
			Usage:   "capture artifacts that were written, executed or found to be suspicious. run '--capture help' for more info.",
		},
		&cli.StringSliceFlag{
			Name:    "cache",
			Aliases: []string{"a"},
			Value:   cli.NewStringSlice("none"),
			Usage:   "Control event caching queues. run '--cache help' for more info.",
		},
		&cli.StringSliceFlag{
			Name:  "crs",
			Usage: "Define connected container runtimes. run '--crs help' for more info.",
			Value: cli.NewStringSlice(),
		},
		&cli.IntFlag{
			Name:    "perf-buffer-size",
			Aliases: []string{"b"},
			Value:   1024, // 4 MB of contigous pages
			Usage:   "size, in pages, of the internal perf ring buffer used to submit events from the kernel",
		},
		&cli.IntFlag{
			Name:  "blob-perf-buffer-size",
			Value: 1024, // 4 MB of contigous pages
			Usage: "size, in pages, of the internal perf ring buffer used to send blobs from the kernel",
		},
		&cli.BoolFlag{
			Name:  "debug",
			Value: false,
			Usage: "write verbose debug messages to standard output and retain intermediate artifacts. enabling will output debug messages to stdout, which will likely break consumers which expect to receive machine-readable events from stdout",
		},
		&cli.BoolFlag{
			Name:  server.MetricsEndpointFlag,
			Usage: "enable metrics endpoint",
			Value: false,
		},
		&cli.BoolFlag{
			Name:  server.HealthzEndpointFlag,
			Usage: "enable healthz endpoint",
			Value: false,
		},
		&cli.BoolFlag{
			Name:  server.PProfEndpointFlag,
			Usage: "enables pprof endpoints",
			Value: false,
		},
		&cli.StringFlag{
			Name:  server.ListenEndpointFlag,
			Usage: "listening address of the metrics endpoint server",
			Value: ":3366",
		},
		&cli.BoolFlag{
			Name:  "containers",
			Usage: "enable container info enrichment to events. **this feature is experimental",
		},
		&cli.StringSliceFlag{
			Name:  flags.CapsMainFlag,
			Usage: fmt.Sprintf("control tracee capabilities dropping functionality. Run '--%s help' for more info", flags.CapsMainFlag),
			Value: cli.NewStringSlice(),
		},
		&cli.StringSliceFlag{
			Name:  "rules",
			Usage: "select which rules to load. Specify multiple rules by repeating this flag. Use --list for rules to select from",
		},
		&cli.StringFlag{
			Name:  "rules-dir",
			Usage: "directory where to search for rules in CEL (.yaml), OPA (.rego), and Go plugin (.so) formats",
		},
		&cli.BoolFlag{
			Name:  "rego-partial-eval",
			Usage: "enable partial evaluation of rego rules",
		},
		&cli.StringFlag{
			Name:  "webhook",
			Usage: "HTTP endpoint to call for every match",
		},
		&cli.StringFlag{
			Name:  "webhook-template",
			Usage: "path to a gotemplate for formatting webhook output",
		},
		&cli.StringFlag{
			Name:  "webhook-content-type",
			Usage: "content type of the template in use. Recommended if using --webhook-template",
		},
		&cli.StringFlag{
			Name:  "output-template",
			Usage: "configure output format via templates. Usage: --output-template=path/to/my.tmpl",
		},
		&cli.BoolFlag{
			Name:  "rego-aio",
			Usage: "compile rego signatures altogether as an aggregate policy. By default each signature is compiled separately.",
		},
		&cli.StringFlag{
			Name:  "rego-runtime-target",
			Usage: "select which runtime target to use for evaluation of rego rules: rego, wasm",
			Value: "rego",
		},
		&cli.UintFlag{
			Name:  "sig-buffer",
			Usage: "size of the event channel's buffer consumed by signatures",
			Value: 1000,
		},
		&cli.BoolFlag{
			Name:  "allow-high-capabilities-for-rules",
			Usage: "allow tracee rules to run with high capabilities if dropping capabilities fails",
			Value: false,
		},
		&cli.StringFlag{
			Name:  "config",
			Usage: "path to config file",
			Value: "config",
		},
	}
}

func trace(c Config) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	exePath := filepath.Dir(exe)

	collect := exec.Command(
		fmt.Sprintf("%s/tracee", exePath),
		getTraceeCollectArguments(c)...,
	)
	collect.Stderr = os.Stderr

	out, err := collect.StdoutPipe()
	if err != nil {
		return err
	}
	defer out.Close()

	err = collect.Start()
	if err != nil {
		logger.Fatal("app", "error", err)
	}

	rules := exec.Command(
		fmt.Sprintf("%s/tracee", exePath),
		getTraceeRulesArguments(c)...,
	)

	rules.Stdin = out
	rules.Stdout = os.Stdout
	rules.Stderr = os.Stderr

	return rules.Run()
}

func getTraceeCollectArguments(c Config) []string {
	arguments := make([]string, 0)

	arguments = append(arguments, "collect")

	arguments = append(arguments, "--output")
	// when using tracee trace, only gob is supported
	arguments = append(arguments, "format:gob")

	if c.Metrics {
		arguments = append(arguments, "--metrics")
	}

	if c.Healthz {
		arguments = append(arguments, "--healthz")
	}

	if c.PProf {
		arguments = append(arguments, "--pprof")
	}

	if c.Debug {
		arguments = append(arguments, "--debug")
	}

	collect := c.Collect

	if collect.Capture.FileWrites {
		arguments = append(arguments, "--capture")
		arguments = append(arguments, "write")
	}

	if collect.Capture.ModuleLoad {
		arguments = append(arguments, "--capture")
		arguments = append(arguments, "module")
	}

	if len(collect.Cache.Type) != 0 {
		arguments = append(arguments, "--cache")
		arguments = append(arguments, fmt.Sprintf("cache-type=%s", collect.Cache.Type))
		if collect.Cache.Type == "mem" && collect.Cache.Size > 0 {
			arguments = append(arguments, "--cache")
			arguments = append(arguments, fmt.Sprintf("mem-cache-size=%d", collect.Cache.Size))
		}
	}

	if collect.ContainerEnrichment {
		arguments = append(arguments, "--containers")
	}

	if collect.PerfBufferSize > 0 {
		arguments = append(arguments, fmt.Sprintf("--perf-buffer-size=%d", collect.PerfBufferSize))
	}

	if collect.BlobPerfBufferSize > 0 {
		arguments = append(arguments, fmt.Sprintf("--blob-perf-buffer-size=%d", collect.BlobPerfBufferSize))
	}

	arguments = append(arguments, "--trace")
	arguments = append(arguments, fmt.Sprintf("event=%s", getEvents(c)))

	return arguments
}

func getTraceeRulesArguments(c Config) []string {
	arguments := make([]string, 0)

	arguments = append(arguments, "rules")

	arguments = append(arguments, "--input-tracee")
	arguments = append(arguments, "format:gob")

	arguments = append(arguments, "--input-tracee")
	arguments = append(arguments, "file:stdin")

	if c.Metrics {
		arguments = append(arguments, "--metrics")
	}

	if c.Healthz {
		arguments = append(arguments, "--healthz")
	}

	if c.PProf {
		arguments = append(arguments, "--pprof")
	}

	if c.Debug {
		arguments = append(arguments, "--debug")
	}

	rego := c.Rules.Rego
	if rego.PartialEval {
		arguments = append(arguments, "--rego-partial-eval")
	}

	if rego.Aio {
		arguments = append(arguments, "--rego-aio")
	}

	if len(rego.RuntimeTarget) > 0 {
		arguments = append(arguments, "--rego-runtime-target")
		arguments = append(arguments, rego.RuntimeTarget)
	}

	if c.Rules.BufferSize > 0 {
		arguments = append(arguments, fmt.Sprintf("--sig-buffer=%d", c.Rules.BufferSize))
	}

	for _, sig := range c.Rules.Signatures {
		arguments = append(arguments, "--rules")
		arguments = append(arguments, sig)
	}

	return arguments
}

func getEvents(c Config) string {
	sigs, err := signatures.GetSignatures(
		c.Rules.Rego.RuntimeTarget,
		c.Rules.Rego.PartialEval,
		// TODO: pass directory
		"",
		c.Rules.Signatures,
		c.Rules.Rego.Aio,
	)
	if err != nil {
		logger.Fatal("app", "error", err)
	}

	var buffer bytes.Buffer
	signatures.ListEvents(&buffer, sigs)

	return strings.TrimSpace(buffer.String())
}
