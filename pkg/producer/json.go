package producer

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/tracee/types/trace"
	"io"
)

type jsonEventProducer struct {
	in *bufio.Scanner
}

func newJsonEventProducer(input io.Reader) *jsonEventProducer {
	scanner := bufio.NewScanner(input)
	scanner.Split(bufio.ScanLines)
	return &jsonEventProducer{in: scanner}
}

func (j jsonEventProducer) Init() error {
	// TODO implement me
	panic("implement me")
}

func (j jsonEventProducer) Produce() (trace.Event, error) {
	if !j.in.Scan() { // if EOF or error close the done channel and return
		// TODO: Create an error for end of stream
		return trace.Event{}, io.EOF
	}

	var e trace.Event
	err := json.Unmarshal(j.in.Bytes(), &e)
	if err != nil {
		return trace.Event{}, fmt.Errorf("failed to unmarshal event - %s", err.Error())
	}
	return e, nil
}
