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
	tracee "github.com/aquasecurity/tracee/tracee/external"
)

func setupStdinSource(inputSource string) (chan types.Event, error) {
	res := make(chan types.Event)
	scanner := bufio.NewScanner(os.Stdin)
	go func() {
		for scanner.Scan() {
			event := scanner.Bytes()
			switch inputSource {
			case "tracee":
				var e tracee.Event
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
	_, err := os.Stat(traceeFilePath)
	if err != nil {
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
		f.Close()
		close(res)
	}()
	return res, nil
}
