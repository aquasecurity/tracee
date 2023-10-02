package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEvent_SetHeader(t *testing.T) {
	t.Parallel()

	evt := Event{
		Headers: EventHeaders{},
		Payload: "blah",
	}

	testHeader := "random-header"

	assert.Equal(t, "", evt.Header(testHeader))

	testHeaderInput := "test"

	evt.SetHeader(testHeader, testHeaderInput)

	assert.Equal(t, testHeaderInput, evt.Header(testHeader))
}
