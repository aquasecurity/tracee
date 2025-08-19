package dependencies

import (
	"errors"
	"fmt"
	"strings"
)

// ErrNodeAddCancelled is the error produced when cancelling a node add to the manager
// using the CancelNodeAddAction Action.
type ErrNodeAddCancelled struct {
	Reasons []error
}

func NewErrNodeAddCancelled(reasons []error) *ErrNodeAddCancelled {
	return &ErrNodeAddCancelled{Reasons: reasons}
}

func (cancelErr *ErrNodeAddCancelled) Error() string {
	var errorsStrings []string
	for _, err := range cancelErr.Reasons {
		errorsStrings = append(errorsStrings, err.Error())
	}
	return fmt.Sprintf("node add was cancelled, reasons: \"%s\"", strings.Join(errorsStrings, "\", \""))
}

func (cancelErr *ErrNodeAddCancelled) AddReason(reason error) {
	cancelErr.Reasons = append(cancelErr.Reasons, reason)
}

// ErrNodeAddFailed is the error returned when a node cannot be added to the manager
// due to a failure triggered by the FailNodeAddAction. This initiates fallback mechanisms.
type ErrNodeAddFailed struct {
	Reasons []error
}

func NewErrNodeAddFailed(reasons []error) *ErrNodeAddFailed {
	return &ErrNodeAddFailed{Reasons: reasons}
}

func (failErr *ErrNodeAddFailed) Error() string {
	var errorsStrings []string
	for _, err := range failErr.Reasons {
		errorsStrings = append(errorsStrings, err.Error())
	}
	return fmt.Sprintf("node add was failed, reasons: \"%s\"", strings.Join(errorsStrings, "\", \""))
}

func (failErr *ErrNodeAddFailed) AddReason(reason error) {
	failErr.Reasons = append(failErr.Reasons, reason)
}

var (
	ErrNodeType     = errors.New("unsupported node type")
	ErrNodeNotFound = errors.New("node not found")
)
