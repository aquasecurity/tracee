package flags

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/errfmt"
)

type PrepareOutputResult struct {
	TraceeConfig   *config.OutputConfig
	PrinterConfigs []config.PrinterConfig
}

func PrepareOutput(outputSlice []string, newBinary bool) (PrepareOutputResult, error) {
	outConfig := PrepareOutputResult{}
	traceeConfig := &config.OutputConfig{}

	// outpath:format
	printerMap := make(map[string]string)

	for _, o := range outputSlice {
		outputParts := strings.SplitN(o, ":", 2)

		if strings.HasPrefix(outputParts[0], "gotemplate=") {
			err := parseFormat(outputParts, printerMap, newBinary)
			if err != nil {
				return outConfig, err
			}
			continue
		}

		switch outputParts[0] {
		case "none":
			if len(outputParts) > 1 {
				if newBinary {
					return outConfig, errors.New("none output does not support path. Run 'man output' for more info")
				}

				return outConfig, errors.New("none output does not support path. Use '--output help' for more info")
			}
			printerMap["stdout"] = "ignore"
		case "table", "table-verbose", "json":
			err := parseFormat(outputParts, printerMap, newBinary)
			if err != nil {
				return outConfig, err
			}
		case "forward":
			err := validateURL(outputParts, "forward", newBinary)
			if err != nil {
				return outConfig, err
			}

			printerMap[outputParts[1]] = "forward"
		case "webhook":
			err := validateURL(outputParts, "webhook", newBinary)
			if err != nil {
				return outConfig, err
			}

			printerMap[outputParts[1]] = "webhook"
		case "option":
			err := parseOption(outputParts, traceeConfig, newBinary)
			if err != nil {
				return outConfig, err
			}
		default:
			if newBinary {
				return outConfig, fmt.Errorf("invalid output flag: %s, run 'man output' for more info", outputParts[0])
			}

			return outConfig, fmt.Errorf("invalid output flag: %s, use '--output help' for more info", outputParts[0])
		}
	}

	// default
	if len(printerMap) == 0 {
		printerMap["stdout"] = "table"
	}

	printerConfigs, err := getPrinterConfigs(printerMap, traceeConfig, newBinary)
	if err != nil {
		return outConfig, err
	}

	outConfig.TraceeConfig = traceeConfig
	outConfig.PrinterConfigs = printerConfigs

	return outConfig, nil
}

// setOption sets the given option in the given config
func setOption(cfg *config.OutputConfig, option string, newBinary bool) error {
	switch option {
	case "stack-addresses":
		cfg.StackAddresses = true
	case "exec-env":
		cfg.ExecEnv = true
	case "relative-time":
		cfg.RelativeTime = true
	case "parse-arguments":
		cfg.ParseArguments = true
	case "parse-arguments-fds":
		cfg.ParseArgumentsFDs = true
		cfg.ParseArguments = true // no point in parsing file descriptor args only
	case "sort-events":
		cfg.EventsSorting = true
	default:
		if strings.HasPrefix(option, "exec-hash") {
			hashExecParts := strings.Split(option, "=")
			if len(hashExecParts) == 1 {
				if option != "exec-hash" {
					goto invalidOption
				}
				// default
				cfg.CalcHashes = config.CalcHashesDevInode
			} else if len(hashExecParts) == 2 {
				hashExecOpt := hashExecParts[1]
				switch hashExecOpt {
				case "none":
					cfg.CalcHashes = config.CalcHashesNone
				case "inode":
					cfg.CalcHashes = config.CalcHashesInode
				case "dev-inode":
					cfg.CalcHashes = config.CalcHashesDevInode
				case "digest-inode":
					cfg.CalcHashes = config.CalcHashesDigestInode
				default:
					goto invalidOption
				}
			} else {
				goto invalidOption
			}

			return nil
		} else {
			goto invalidOption
		}

	invalidOption:
		if newBinary {
			return errfmt.Errorf("invalid output option: %s, run 'man output' for more info", option)
		}

		return errfmt.Errorf("invalid output option: %s, use '--output help' for more info", option)
	}

	return nil
}

// getPrinterConfigs returns a slice of printer.Configs based on the given printerMap
func getPrinterConfigs(printerMap map[string]string, traceeConfig *config.OutputConfig, newBinary bool) ([]config.PrinterConfig, error) {
	printerConfigs := make([]config.PrinterConfig, 0, len(printerMap))

	for outPath, printerKind := range printerMap {
		if printerKind == "table" {
			if err := setOption(traceeConfig, "parse-arguments", newBinary); err != nil {
				return nil, err
			}
		}

		outFile := os.Stdout
		var err error

		if outPath != "stdout" && printerKind != "forward" && printerKind != "webhook" {
			outFile, err = createFile(outPath)
			if err != nil {
				return nil, err
			}
		}

		printerConfigs = append(printerConfigs, config.PrinterConfig{
			Kind:       printerKind,
			OutPath:    outPath,
			OutFile:    outFile,
			RelativeTS: traceeConfig.RelativeTime,
		})
	}

	return printerConfigs, nil
}

// parseFormat parses the given format and sets it in the given printerMap
func parseFormat(outputParts []string, printerMap map[string]string, newBinary bool) error {
	// if not file was passed, we use stdout
	if len(outputParts) == 1 {
		outputParts = append(outputParts, "stdout")
	}

	for _, outPath := range strings.Split(outputParts[1], ",") {
		if outPath == "" {
			if newBinary {
				return errfmt.Errorf("format flag can't be empty, run 'man output' for more info")
			}

			return errfmt.Errorf("format flag can't be empty, use '--output help' for more info")
		}

		if _, ok := printerMap[outPath]; ok {
			if newBinary {
				return errfmt.Errorf("cannot use the same path for multiple outputs: %s, run  'man output' for more info", outPath)
			}

			return errfmt.Errorf("cannot use the same path for multiple outputs: %s, use '--output help' for more info", outPath)
		}
		printerMap[outPath] = outputParts[0]
	}

	return nil
}

// parseOption parses the given option and sets it in the given config
func parseOption(outputParts []string, traceeConfig *config.OutputConfig, newBinary bool) error {
	if len(outputParts) == 1 || outputParts[1] == "" {
		if newBinary {
			return errfmt.Errorf("option flag can't be empty, run 'man output' for more info")
		}

		return errfmt.Errorf("option flag can't be empty, use '--output help' for more info")
	}

	for _, option := range strings.Split(outputParts[1], ",") {
		err := setOption(traceeConfig, option, newBinary)
		if err != nil {
			return err
		}
	}

	return nil
}

// creates *os.File for the given path
func createFile(path string) (*os.File, error) {
	fileInfo, err := os.Stat(path)
	if err == nil && fileInfo.IsDir() {
		return nil, errfmt.Errorf("cannot use a path of existing directory %s", path)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, errfmt.Errorf("failed to create directory: %v", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, errfmt.Errorf("failed to create output path: %v", err)
	}

	return file, nil
}

// validateURL validates the given URL
// --output [webhook|forward]:[protocol://user:pass@]host:port[?k=v#f]
func validateURL(outputParts []string, flag string, newBinary bool) error {
	if len(outputParts) == 1 || outputParts[1] == "" {
		if newBinary {
			return errfmt.Errorf("%s flag can't be empty, run 'man output' for more info", flag)
		}

		return errfmt.Errorf("%s flag can't be empty, use '--output help' for more info", flag)
	}
	// Now parse our URL using the standard library and report any errors from basic parsing.
	_, err := url.ParseRequestURI(outputParts[1])

	if err != nil {
		if newBinary {
			return errfmt.Errorf("invalid uri for %s output %q. Run 'man output' for more info", flag, outputParts[1])
		}

		return errfmt.Errorf("invalid uri for %s output %q. Use '--output help' for more info", flag, outputParts[1])
	}

	return nil
}
