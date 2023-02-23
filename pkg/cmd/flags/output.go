package flags

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/logger"
)

func outputHelp() string {
	return `Control how and where output is printed.
Possible options:
[format:]table                                     output events in table format
[format:]table-verbose                             output events in table format with extra fields per event
[format:]json                                      output events in json format
[format:]gob                                       output events in gob format
[format:]gotemplate=/path/to/template              output events formatted using a given gotemplate file
forward:url                                        send events in json format using the Forward protocol to a Fluent receiver
out-file:/path/to/file                             write the output to a specified file. create/trim the file if exists (default: stdout)
log-file:/path/to/file                             write the logs to a specified file. create/trim the file if exists (default: stderr)
none                                               ignore stream of events output, usually used with --capture
option:{stack-addresses,exec-env,relative-time,exec-hash,parse-arguments,sort-events}
                                                   augment output according to given options (default: none)
  stack-addresses                                  include stack memory addresses for each event
  exec-env                                         when tracing execve/execveat, show the environment variables that were used for execution
  relative-time                                    use relative timestamp instead of wall timestamp for events
  exec-hash                                        when tracing sched_process_exec, show the file hash(sha256) and ctime
  parse-arguments                                  do not show raw machine-readable values for event arguments, instead parse into human readable strings
  parse-arguments-fds                              enable parse-arguments and enrich fd with its file path translation. This can cause pipeline slowdowns.
  sort-events                                      enable sorting events before passing to them output. This will decrease the overall program efficiency.
Examples:
  --output json                                                    | output as json
  --output gotemplate=/path/to/my.tmpl                             | output as the provided go template
  --output out-file:/my/out --output log-file:/my/log              | output to /my/out and logs to /my/log
  --output forward:tcp://user:pass@127.0.0.1:24224?tag=tracee      | output via the Forward protocol to 127.0.0.1 on port 24224 with the tag 'tracee' using TCP
  --output none                                                    | ignore events output
Use this flag multiple times to choose multiple output options
`
}

type OutputConfig struct {
	TraceeConfig  *tracee.OutputConfig
	PrinterConfig printer.Config
	LogFile       *os.File
}

func PrepareOutput(outputSlice []string) (OutputConfig, error) {
	outConfig := OutputConfig{}
	traceeConfig := &tracee.OutputConfig{}
	printerConfig := printer.Config{}

	var outPath string
	var logPath string
	printerKind := "table"

	for _, o := range outputSlice {
		// Forward uses the net/url library to handle a full url including protocol, etc. so must cope with embedded colon characters
		if strings.HasPrefix(o, "forward:") {
			// Validate the forward configuration details which are as follows:
			// --output forward:[protocol://user:pass@]host:port[?k=v#f]
			// Only host and port are required.

			forwardURL, err := parseForwardFlag(o)
			if err != nil {
				return outConfig, err
			}

			printerKind = "forward"
			// Deliberately lightweight to just pass the URL into the printer config.
			// We handle the specific configuration and other checks as part of the Init() call there.
			printerConfig.ForwardURL = forwardURL

			continue
		}

		outputParts := strings.SplitN(o, ":", 2)
		numParts := len(outputParts)
		if numParts == 1 && outputParts[0] != "none" {
			outputParts = append(outputParts, outputParts[0])
			outputParts[0] = "format"
		}

		switch outputParts[0] {
		case "none":
			printerKind = "ignore"
		case "format":
			printerKind = outputParts[1]
			if err := validateFormat(printerKind); err != nil {
				return outConfig, err
			}
		case "out-file":
			outPath = outputParts[1]
		case "log-file":
			logPath = outputParts[1]
		case "option":
			switch outputParts[1] {
			case "stack-addresses":
				traceeConfig.StackAddresses = true
			case "exec-env":
				traceeConfig.ExecEnv = true
			case "relative-time":
				traceeConfig.RelativeTime = true
				printerConfig.RelativeTS = true
			case "exec-hash":
				traceeConfig.ExecHash = true
			case "parse-arguments":
				traceeConfig.ParseArguments = true
			case "parse-arguments-fds":
				traceeConfig.ParseArgumentsFDs = true
				traceeConfig.ParseArguments = true // no point in parsing file descriptor args only
			case "sort-events":
				traceeConfig.EventsSorting = true
			default:
				return outConfig, logger.NewErrorf("invalid output option: %s, use '--output help' for more info", outputParts[1])
			}
		default:
			return outConfig, logger.NewErrorf("invalid output value: %s, use '--output help' for more info", outputParts[1])
		}
	}

	if printerKind == "table" {
		traceeConfig.ParseArguments = true
	}

	printerConfig.Kind = printerKind

	if outPath == "" {
		printerConfig.OutFile = os.Stdout
	} else {
		file, err := createFile(outPath)
		if err != nil {
			return outConfig, err
		}

		printerConfig.OutPath = outPath
		printerConfig.OutFile = file
	}

	if logPath == "" {
		outConfig.LogFile = os.Stderr
	} else {
		file, err := createFile(logPath)
		if err != nil {
			return outConfig, err
		}

		outConfig.LogFile = file
	}

	outConfig.TraceeConfig = traceeConfig
	outConfig.PrinterConfig = printerConfig

	return outConfig, nil
}

func validateFormat(printerKind string) error {
	if printerKind != "table" &&
		printerKind != "table-verbose" &&
		printerKind != "json" &&
		printerKind != "gob" &&
		!strings.HasPrefix(printerKind, "gotemplate=") {
		return logger.NewErrorf("unrecognized output format: %s. Valid format values: 'table', 'table-verbose', 'json', 'gob' or 'gotemplate='. Use '--output help' for more info", printerKind)
	}

	return nil
}

func createFile(path string) (*os.File, error) {
	fileInfo, err := os.Stat(path)
	if err == nil && fileInfo.IsDir() {
		return nil, logger.NewErrorf("cannot use a path of existing directory %s", path)
	}

	dir := filepath.Dir(path)
	os.MkdirAll(dir, 0755)
	file, err := os.Create(path)
	if err != nil {
		return nil, logger.NewErrorf("failed to create output path: %v", err)
	}

	return file, nil
}

func parseForwardFlag(o string) (*url.URL, error) {
	// Split out just the config
	forwardConfigParts := strings.SplitN(o, ":", 2)
	if len(forwardConfigParts) != 2 {
		return nil, logger.NewErrorf("invalid configuration for forward output: %q. Use '--output help' for more info", o)
	}
	// Now parse our URL using the standard library and report any errors from basic parsing.
	forwardURL, err := url.Parse(forwardConfigParts[1])
	if err != nil {
		return nil, logger.NewErrorf("invalid configuration for forward output (%s): %v. Use '--output help' for more info", forwardConfigParts[1], err)
	}

	return forwardURL, nil
}
