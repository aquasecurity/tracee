package proto

import (
	"errors"
	"fmt"
)

var ErrInvalidArgument = errors.New("invalid argument")

func FailArgWrapError(argVal string) error {
	return fmt.Errorf("failed wrapping arg type %s", argVal)
}

func FailArgUnwrapError(argVal string) error {
	return fmt.Errorf("failed unwrapping arg type %s", argVal)
}
