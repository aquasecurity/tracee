package flags

import (
	"os"
	"strings"

	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/errfmt"
)

func traceeEbpfOutputHelp() string {
	return `Control how and where output is printed.
Possible options:
[format:]table                                     output events in table format (default)
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
Examples:
  --output json                                            | output as json to stdout
  --output gotemplate=/path/to/my.tmpl                     | output as the provided go template
  --output out-file:/my/out --output log-file:/my/log      | output to /my/out and logs to /my/log
  --output none                                            | ignore events output
Use this flag multiple times to choose multiple output options
`
}

func TraceeEbpfPrepareOutput(outputSlice []string) (OutputConfig, error) {
	outConfig := OutputConfig{}
	traceeConfig := &tracee.OutputConfig{}

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
			err := setOption(traceeConfig, outputParts[1])
			if err != nil {
				return outConfig, err
			}
		default:
			return outConfig, errfmt.Errorf("invalid output value: %s, use '--output help' for more info", outputParts[1])
		}
	}

	printerConfigs := make([]printer.Config, 0)

	if printerKind == "table" {
		if err := setOption(traceeConfig, "parse-arguments"); err != nil {
			return outConfig, err
		}
	}

	if outPath == "" {
		stdoutConfig := printer.Config{
			Kind:       printerKind,
			OutFile:    os.Stdout,
			RelativeTS: traceeConfig.RelativeTime,
		}

		printerConfigs = append(printerConfigs, stdoutConfig)
	} else {
		file, err := createFile(outPath)
		if err != nil {
			return outConfig, err
		}

		printerConfig := printer.Config{
			Kind:       printerKind,
			OutPath:    outPath,
			OutFile:    file,
			RelativeTS: traceeConfig.RelativeTime,
		}

		printerConfigs = append(printerConfigs, printerConfig)
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
	outConfig.PrinterConfigs = printerConfigs

	return outConfig, nil
}

func validateFormat(printerKind string) error {
	if printerKind != "table" &&
		printerKind != "table-verbose" &&
		printerKind != "json" &&
		printerKind != "gob" &&
		!strings.HasPrefix(printerKind, "gotemplate=") {
		return errfmt.Errorf("unrecognized output format: %s. Valid format values: 'table', 'table-verbose', 'json', 'gob' or 'gotemplate='. Use '--output help' for more info", printerKind)
	}

	return nil
}
