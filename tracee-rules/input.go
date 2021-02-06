package main

import (
	"bufio"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/aquasecurity/tracee/tracee-rules/types"
	tracee "github.com/aquasecurity/tracee/tracee/external"
)

var errHelp = errors.New("user has requested help text")

type inputFormat uint8

const (
	invalidInputFormat inputFormat = iota
	jsonInputFormat
	gobInputFormat
)

type traceeInputOptions struct {
	inputFile   *os.File
	inputFormat inputFormat
}

func setupTraceeInputSource(opts *traceeInputOptions) (chan types.Event, error) {

	if opts.inputFormat == jsonInputFormat {
		return setupTraceeJSONInputSource(opts)
	}

	if opts.inputFormat == gobInputFormat {
		return setupTraceeGobInputSource(opts)
	}

	return nil, errors.New("could not set up input source")
}

func setupTraceeGobInputSource(opts *traceeInputOptions) (chan types.Event, error) {
	dec := gob.NewDecoder(opts.inputFile)
	res := make(chan types.Event)
	go func() {
		for {
			var event tracee.Event
			err := dec.Decode(&event)
			if err != nil {
				if err == io.EOF {
					break
				} else {
					log.Printf("Error while decoding event: %v", err)
				}
			} else {
				res <- event
			}
		}
		opts.inputFile.Close()
		close(res)
	}()
	return res, nil
}

func setupTraceeJSONInputSource(opts *traceeInputOptions) (chan types.Event, error) {
	res := make(chan types.Event)
	scanner := bufio.NewScanner(opts.inputFile)
	go func() {
		for scanner.Scan() {
			event := scanner.Bytes()
			var e tracee.Event
			err := json.Unmarshal(event, &e)
			if err != nil {
				log.Printf("invalid json in %s: %v", string(event), err)
			}
			res <- e
		}
		opts.inputFile.Close()
		close(res)
	}()
	return res, nil
}

func parseTraceeInputOptions(inputOptions []string) (*traceeInputOptions, error) {

	var (
		inputSourceOptions traceeInputOptions
		err                error
	)

	if len(inputOptions) == 0 {
		return nil, errors.New("no tracee input options specified")
	}

	for i := range inputOptions {
		if inputOptions[i] == "help" {
			return nil, errHelp
		}

		kv := strings.Split(inputOptions[i], ":")
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid input-tracee option: %s", inputOptions[i])
		}
		if kv[0] == "" || kv[1] == "" {
			return nil, fmt.Errorf("empty key or value passed: key: >%s< value: >%s<", kv[0], kv[1])
		}
		if kv[0] == "file" {
			err = parseTraceeInputFile(&inputSourceOptions, kv[1])
			if err != nil {
				return nil, err
			}
		} else if kv[0] == "format" {
			err = parseTraceeInputFormat(&inputSourceOptions, kv[1])
			if err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("invalid input-tracee option key: %s", kv[0])
		}
	}
	return &inputSourceOptions, nil
}

func parseTraceeInputFile(option *traceeInputOptions, fileOpt string) error {

	if fileOpt == "stdin" {
		option.inputFile = os.Stdin
		return nil
	}
	_, err := os.Stat(fileOpt)
	if err != nil {
		return fmt.Errorf("invalid Tracee input file: %s", fileOpt)
	}
	f, err := os.Open(fileOpt)
	if err != nil {
		return fmt.Errorf("invalid file: %s", fileOpt)
	}
	option.inputFile = f
	return nil
}

func parseTraceeInputFormat(option *traceeInputOptions, formatString string) error {
	formatString = strings.ToUpper(formatString)

	if formatString == "JSON" {
		option.inputFormat = jsonInputFormat
	} else if formatString == "GOB" {
		option.inputFormat = gobInputFormat
	} else {
		option.inputFormat = invalidInputFormat
		return fmt.Errorf("invalid tracee input format specified: %s", formatString)
	}
	return nil
}

func printHelp() {
	traceeInputHelp := `
tracee-rules --input-tracee <key:value>,<key:value> --input-tracee <key:value>

Specify various key value pairs for input options tracee-ebpf. The following key options are available:

'file'   - Input file source. You can specify a relative or absolute path. You may also specify 'stdin' for standard input.
'format' - Input format. Options currently include 'JSON' and 'GOB'. Both can be specified as output formats from tracee-ebpf.

Examples:

'tracee-rules --input-tracee file:./events.json --input-tracee format:json'
'tracee-rules --input-tracee file:./events.gob --input-tracee format:gob'
'sudo tracee-ebpf -o format:gob | tracee-rules --input-tracee file:stdin --input-tracee format:gob'
`

	fmt.Println(traceeInputHelp)
}
