package main

import (
	"bufio"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/aquasecurity/tracee/tracee-rules/types"
)

func setupStdinSource(inputSource string) (chan types.Event, error) {
	res := make(chan types.Event)
	scanner := bufio.NewScanner(os.Stdin)
	go func() {
		for scanner.Scan() {
			event := scanner.Bytes()
			switch inputSource {
			case "tracee":
				var e types.TraceeEvent
				err := json.Unmarshal(event, &e)
				if err != nil {
					log.Printf("invalid json in %s: %v", string(event), err)
				}
				res <- types.Event(e)
			}
		}
		close(res)
	}()
	return res, nil
}

func setupTraceeSource(traceeFilePath string) (chan types.Event, error) {
	fi, err := os.Stat(traceeFilePath)
	if err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("invalid Tracee input file: %s", traceeFilePath)
	}
	f, err := os.Open(traceeFilePath)
	if err != nil {
		return nil, fmt.Errorf("invalid file: %s", traceeFilePath)
	}
	dec := gob.NewDecoder(f)
	res := make(chan types.Event)
	go func() {
		for {
			var event types.TraceeEvent
			err := dec.Decode(&event)
			if err != nil {
				if err == io.EOF {
					// ignore EOF becasue we assume events can keep streaming into the file
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
		f.Close()
		close(res)
	}()
	return res, nil
}
