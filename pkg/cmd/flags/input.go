package flags

import (
	"fmt"
	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	cap2 "kernel.org/pub/linux/libs/security/libcap/cap"
	"os"
	"strings"
)

func PrepareInput(inputOption string) (*config.ProducerConfig, error) {
	var (
		inputSourceOptions config.ProducerConfig
		err                error
	)

	inParts := strings.SplitN(inputOption, ":", 2)

	switch inParts[0] {
	case "json", "rego":
		inputSourceOptions.Kind = inParts[0]
		var fileOpt string
		switch len(inParts) {
		case 1:
			fileOpt = "stdin"
		case 2:
			fileOpt = inParts[1]
		default:
			return &inputSourceOptions, fmt.Errorf(
				"invalid input option: %s, use '--input help' for more info",
				inputOption,
			)
		}
		err = parseTraceeInputSource(&inputSourceOptions, fileOpt)
		if err != nil {
			return &inputSourceOptions, err
		}
	default:
		return &inputSourceOptions, fmt.Errorf(
			"invalid output flag: %s, use '--help' for more info",
			inputOption[0],
		)
	}
	return &inputSourceOptions, nil
}

func parseTraceeInputSource(option *config.ProducerConfig, fileOpt string) error {
	var f *os.File

	if fileOpt == "stdin" {
		option.InputSource = os.Stdin
		return nil
	}
	err := capabilities.GetInstance().Specific(
		func() error {
			_, err := os.Stat(fileOpt)
			if err != nil {
				return errfmt.Errorf("invalid Tracee input file: %s", fileOpt)
			}
			f, err = os.Open(fileOpt)
			if err != nil {
				return errfmt.Errorf("invalid file: %s", fileOpt)
			}
			return nil
		},
		cap2.DAC_OVERRIDE,
	)
	if err != nil {
		return errfmt.WrapError(err)
	}
	option.InputSource = f

	return nil
}
