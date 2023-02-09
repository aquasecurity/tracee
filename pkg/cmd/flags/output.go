package flags

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
)

func outputHelp() string {
	return `Control how and where output is printed.
Possible options:
[format:]table                                     output events in table format
[format:]table-verbose                             output events in table format with extra fields per event
[format:]json                                      output events in json format
[format:]gob                                       output events in gob format
[format:]gotemplate=/path/to/template              output events formatted using a given gotemplate file
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
  cache-events                                     enable caching events to release perf-buffer pressure. This will decrease amount of event loss until cache is full.
Examples:
  --output json                                            | output as json to stdout
  --output gotemplate=/path/to/my.tmpl                     | output as the provided go template
  --output out-file:/my/out --output log-file:/my/log      | output to /my/out and logs to /my/log
  --output none                                            | ignore events output
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
				return outConfig, fmt.Errorf("invalid output option: %s, use '--output help' for more info", outputParts[1])
			}
		default:
			return outConfig, fmt.Errorf("invalid output value: %s, use '--output help' for more info", outputParts[1])
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
		return fmt.Errorf("unrecognized output format: %s. Valid format values: 'table', 'table-verbose', 'json', 'gob' or 'gotemplate='. Use '--output help' for more info", printerKind)
	}

	return nil
}

func createFile(path string) (*os.File, error) {
	fileInfo, err := os.Stat(path)
	if err == nil && fileInfo.IsDir() {
		return nil, fmt.Errorf("cannot use a path of existing directory %s", path)
	}

	dir := filepath.Dir(path)
	os.MkdirAll(dir, 0755)
	file, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create output path: %v", err)
	}

	return file, nil
}
