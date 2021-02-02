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
	"time"

	"github.com/aquasecurity/tracee/tracee-rules/types"
	tracee "github.com/aquasecurity/tracee/tracee/external"
)

type inputFormat uint8

const (
	invalidInputFormat inputFormat = iota + 1
	jsonInputFormat
	gobInputFormat
)

type traceeInputOptions struct {
	inputFile   *os.File
	inputFormat inputFormat
	closeOnEOF  bool
}

func setupInputSource(opts *traceeInputOptions) (chan types.Event, error) {

	if opts.inputFormat == jsonInputFormat {
		return setupJSONInputSource(opts)
	}

	if opts.inputFormat == gobInputFormat {
		return setupGobInputSource(opts)
	}

	return nil, errors.New("could not set up input source")
}

func setupGobInputSource(opts *traceeInputOptions) (chan types.Event, error) {
	dec := gob.NewDecoder(opts.inputFile)
	res := make(chan types.Event)
	go func() {
		for {
			var event tracee.Event
			err := dec.Decode(&event)
			if err != nil {
				if err == io.EOF {
					// ignore EOF because we assume events can keep streaming into the file
					// this might create a backlog of events and depending on the implementation of the input source might lead to lost events
					// TODO: investigate impact of this and research alternatives
					time.Sleep(time.Millisecond * 150)
					continue
				} else {
					log.Printf("Error while decoding event: %v", err)
				}
			} else if event.EventName[0] == 4 { // Tracee EOT signal
				break
			} else {
				res <- event
			}
		}
		opts.inputFile.Close()
		close(res)
	}()
	return res, nil
}

func setupJSONInputSource(opts *traceeInputOptions) (chan types.Event, error) {
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
			res <- tracee.Event(e)
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
			printHelp()
			os.Exit(0)
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
		} else if kv[0] == "option" {
			err = parseTraceeInputOption(&inputSourceOptions, kv[1])
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

func parseTraceeInputOption(option *traceeInputOptions, optionString string) error {
	if strings.ToUpper(optionString) == "EOF" {
		option.closeOnEOF = true
	} else {
		return fmt.Errorf("unkown tracee input option: %s", optionString)
	}
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
'sudo tracee-ebpf -o format:gob -o option:eot | tracee-rules --input-tracee file:stdin --input-tracee format:gob'
`

	fmt.Println(traceeInputHelp)
}
