package errfmt

import (
	"fmt"
	"runtime"
	"strings"
)

// funcName returns the name of the function that called it based on the
// skip value. 0 is the current function, 1 is the caller of the current
// function, etc.
func funcName(skip int) string {
	pc, _, _, _ := runtime.Caller(skip + 1)
	funcName := runtime.FuncForPC(pc).Name()
	index := strings.LastIndex(funcName, "/") + 1

	return funcName[index:]
}

// prefixFunc prefixes a given string with the name of the function that
// called it based on the skip value.
func prefixFunc(msg string, skip int) error {
	fName := funcName(skip + 1)

	return fmt.Errorf("%v: %v", fName, msg)
}

// prefixFuncError prefixes a given error with the name of the function that
// called it based on the skip value, preserving the error chain.
func prefixFuncError(err error, skip int) error {
	fName := funcName(skip + 1)

	return fmt.Errorf("%v: %w", fName, err)
}

// Errorf returns an error prefixed by the current (caller) function name
// and formatted with the given arguments.
func Errorf(format string, a ...interface{}) error {
	sentence := fmt.Sprintf(format, a...)
	if sentence == "" {
		return nil
	}

	return prefixFunc(sentence, 1)
}

// WrapError returns the given error prefixed by the current (caller) function
// name while preserving the error chain.
func WrapError(e error) error {
	if e == nil {
		return nil
	}

	return prefixFuncError(e, 1)
}
