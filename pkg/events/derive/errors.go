package derive

import (
	"errors"
	"fmt"

	"github.com/aquasecurity/tracee/pkg/events"
)

func deriveError(id events.ID, err error) error {
	return fmt.Errorf("failed to derive event %d: %v", id, err)
}

func unexpectedArgCountError(name string, expected int, actual int) error {
	return fmt.Errorf("error deriving event \"%s\": expected %d arguments but given %d", name, expected, actual)
}

func alreadyRegisteredError(from, to events.ID) error {
	return fmt.Errorf("event derivation from %d to %d already exists", from, to)
}

//
// Network Events
//

func noPayloadError() error {
	return errors.New("no payload ?")
}

func emptyPayloadError() error {
	return errors.New("empty payload ?")
}

func nonByteArgError() error {
	return errors.New("non []byte argument ?")
}

func parsePacketError() error {
	return errors.New("could not parse packet")
}

func notProtoPacketError(proto string) error {
	return fmt.Errorf("not a %s packet", proto)
}
